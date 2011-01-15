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

// GLOBALS
extern bool is_daemonised;
extern OptionContainer o;

// class name is relevant!
class sqlauthinstance:public AuthPlugin
{
public:
	// Keep credentials for the whole of a connection - IP isn't going to 
	// change. Not quite true - what about downstream proxy with 
	// x-forwarded-for?
	sqlauthinstance(ConfigVar &definition):AuthPlugin(definition)
	{
		if (!o.use_xforwardedfor)
			is_connection_based = true;
	};

	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);
	int determineGroup(std::string &user, int &fg);

	int init(void* args);
	int quit();
protected:
	std::string connection_string;
	ConfigVar groupmap;
	std::map <std::string, std::string> ipuser_cache;
	std::map <std::string, int> userfg_cache;
	time_t cache_timestamp;
	double cache_ttl; // difftime() returns double
	bool flush_cache_if_too_old();
};

// IMPLEMENTATION

// Class factory code *MUST* be included in every plugin
AuthPlugin *sqlauthcreate(ConfigVar & definition)
{
	return new sqlauthinstance(definition);
}

int sqlauthinstance::quit() {
	ipuser_cache.clear();
	userfg_cache.clear();
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
	
	if (ipuser_cache.count(ipstring)) { 
		string = ipuser_cache[ipstring];
		return DGAUTH_OK;
	} else { // query the db
		String sql_query( cv["sqlauthipuserquery"] );
		sql_query.replaceall("-IPADDRESS-", ipstring.c_str());
		try {
			soci::session sql(cv["sqlauthdb"], connection_string);
			soci::indicator ind;
			sql << sql_query, soci::into(string, ind);
			if ( ind == soci::i_ok ) {
				ipuser_cache[ipstring] = string;
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
}

int sqlauthinstance::determineGroup(std::string &user, int &fg)
{
	flush_cache_if_too_old();

	if (userfg_cache.count(user)) {
		fg = userfg_cache[user];
		return DGAUTH_OK;
	}		

	String sql_query( cv["sqlauthusergroupquery"] );
	sql_query.replaceall("-USERNAME-", user.c_str());
	std::vector<std::string> sqlgroups(32); // will be shrinked
	try {
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
					userfg_cache[user] = fg;
					return DGAUTH_OK;
				}
			}
		}
	return DGAUTH_NOMATCH;
}

bool sqlauthinstance::flush_cache_if_too_old()
{
	if (difftime(time(NULL), cache_timestamp) > cache_ttl) {
		ipuser_cache.clear();
		userfg_cache.clear();
		cache_timestamp = time(NULL);
		return true;
	}
	return false;
}
