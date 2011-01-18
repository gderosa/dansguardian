// IP SQL auth plugin -- by Guido De Rosa <guido.derosa * vemarsas.it>

// Please refer to http://dansguardian.org/?page=copyright2
// for the license for this code.

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../Auth.hpp"
#include "../OptionContainer.hpp"
#include "../String.hpp"

#include <syslog.h>
#include <algorithm>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>

#include <soci/soci.h>

// http://www.boost.org/doc/libs/1_45_0/doc/html/interprocess/quick_guide.html#interprocess.quick_guide.qg_interprocess_map
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <functional>
#include <utility>

using namespace boost::interprocess;

typedef std::string ipType;
typedef std::string userType;
typedef int fgType;
typedef std::pair<ipType, userType> ipuserPair;
typedef std::pair<userType, fgType> userfgPair;
typedef allocator<ipuserPair, managed_shared_memory::segment_manager>
	ipuserAllocator;
typedef allocator<userfgPair, managed_shared_memory::segment_manager>
	userfgAllocator;
typedef map<ipType, userType, std::less<ipType>, ipuserAllocator> ipuserMap;
typedef map<userType, fgType, std::less<userType>, userfgAllocator> userfgMap;


// GLOBALS
extern bool is_daemonised;
extern OptionContainer o;


// class name is relevant!
class sqlauthinstance:public AuthPlugin
{
public:
	sqlauthinstance(ConfigVar &definition);

	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);
	int determineGroup(std::string &user, int &fg);

	int init(void* args);
	int quit();
protected:
	std::string connection_string;
	ConfigVar groupmap;
	ipuserMap * ipuser_cache;
	userfgMap * userfg_cache;
	time_t cache_timestamp;
	double cache_ttl; // difftime() returns double
	bool flush_cache_if_too_old();
	managed_shared_memory ipuser_segment;
	managed_shared_memory userfg_segment;
	ipuserAllocator ipuser_alloca;
	userfgAllocator userfg_alloca;
};

// IMPLEMENTATION

// Class factory code *MUST* be included in every plugin
AuthPlugin *sqlauthcreate(ConfigVar & definition)
{
	return new sqlauthinstance(definition);
}

sqlauthinstance::sqlauthinstance(ConfigVar &definition):
	AuthPlugin(definition),
	ipuser_segment(create_only, "dg_sqlauth_ipuser", 65536),
	userfg_segment(create_only, "dg_sqlauth_userfg", 65536),
	ipuser_alloca(ipuser_segment.get_segment_manager()),
	userfg_alloca(userfg_segment.get_segment_manager())
{
	// Keep credentials for the whole of a connection - IP isn't going to 
	// change. Not quite true - what about downstream proxy with 
	// x-forwarded-for?
	if (!o.use_xforwardedfor)
		is_connection_based = true;
}


int sqlauthinstance::quit() {
	return 0;
}

int sqlauthinstance::init(void* args) {
	connection_string = 
		"host='"     + cv["sqlauthdbhost"] + "' " +
		"db='"       + cv["sqlauthdbname"] + "' " + 
		"user='"     + cv["sqlauthdbuser"] + "' " +
		"password='" + cv["sqlauthdbpass"] + "'"  ;
	groupmap.readVar(cv["sqlauthgroups"].c_str(), "=");
	cache_ttl = atof(cv["sqlauthcachettl"].c_str());
	cache_timestamp = time(NULL); 

	ipuser_cache =
		ipuser_segment.construct<ipuserMap>("ipuser_cache")      //object name
                                 (std::less<ipType>() //first  ctor parameter
                                 ,ipuser_alloca);     //second ctor parameter
	userfg_cache =
		userfg_segment.construct<userfgMap>("userfg_cache")      //object name
                                 (std::less<userType>() //first  ctor parameter
                                 ,userfg_alloca);     //second ctor parameter
	return 0;
}

int sqlauthinstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string)
{
	flush_cache_if_too_old();

	std::string ipstring;

	if (o.use_xforwardedfor) {
		// grab the X-Forwarded-For IP if available
		ipstring = h.getXForwardedForIP();
		// otherwise, grab the IP directly from the client connection
		if (ipstring.length() == 0)
			ipstring = peercon.getPeerIP();
	} else {
		ipstring = peercon.getPeerIP();
	}
	
	if (ipuser_cache->count(ipstring)) { 
		string = (*ipuser_cache)[ipstring];
		return DGAUTH_OK;
	}
	
	// query the db
	String sql_query( cv["sqlauthipuserquery"] );
	sql_query.replaceall("-IPADDRESS-", ipstring.c_str());
	try {
		if (cv["sqlauthdebug"] == "on") {
			if (!is_daemonised) 
				std::cout << time(NULL) << ": " << sql_query << std::endl;
		}
		soci::session sql(cv["sqlauthdb"], connection_string);
		soci::indicator ind;
		sql << sql_query, soci::into(string, ind);
		if ( ind == soci::i_ok ) {
			//(*ipuser_cache)[ipstring] = string;
			ipuser_cache->insert(ipuserPair(ipstring, string));
			return DGAUTH_OK;
		} else {
			return DGAUTH_NOMATCH;
		}
	}
	catch (std::exception const &e) {
		if (!is_daemonised) 
			std::cerr << "sqlauthinstance::identify(): " << e.what() << '\n';
		syslog(LOG_ERR, "sqlauthinstance::identify(): %s", e.what());
		return DGAUTH_NOMATCH; // allow other plugins to work
	}
}

int sqlauthinstance::determineGroup(std::string &user, int &fg)
{
	flush_cache_if_too_old();

	if (userfg_cache->count(user)) {
		fg = (*userfg_cache)[user];
		return DGAUTH_OK;
	}		

	String sql_query( cv["sqlauthusergroupquery"] );
	sql_query.replaceall("-USERNAME-", user.c_str());
	std::vector<std::string> sqlgroups(32); // will be shrinked
	try {
		if (cv["sqlauthdebug"] == "on") {
			if (!is_daemonised) 
				std::cout << time(NULL) << ": " << sql_query << std::endl;
		}	
		soci::session sql(cv["sqlauthdb"], connection_string);
		sql << sql_query, soci::into(sqlgroups);
	}
	catch (std::exception const &e) {
		if (!is_daemonised) 
			std::cerr << "sqlauthinstance::determineGroup(): " << e.what() << '\n';
		syslog(LOG_ERR, "sqlauthinstance::determineGroup(): %s", e.what());
		return DGAUTH_NOMATCH; // allow other plugins to work
	}
	for (unsigned int i=0; i<sqlgroups.size(); i++)	 {
		String filtername = groupmap[ sqlgroups[i].c_str() ];
		if ( filtername.size() > 0 ) { 
			fg = filtername.after("filter").toInteger();
				if (fg > 0) {
					fg--;
					//(*userfg_cache)[user] = fg;
					userfg_cache->insert(userfgPair(user, fg));
					return DGAUTH_OK;
				}
			}
		}
	return DGAUTH_NOMATCH;
}

bool sqlauthinstance::flush_cache_if_too_old()
{
	if (difftime(time(NULL), cache_timestamp) > cache_ttl) {
		ipuser_cache->clear();
		userfg_cache->clear();
		cache_timestamp = time(NULL);
		return true;
	}
	return false;
}
