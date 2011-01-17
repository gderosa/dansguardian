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

#include <fcntl.h>
#include <sys/mman.h> // shm_open(), mmap() and friends

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
	
	struct ipuser_POD_pair{
		char ip[256]; // be large even for IPv6 addresses... :-)
		char user[256];
	} * ipuser_shared_pair;

	struct userfg_POD_pair{
		char user[256];
		int fg;
	} * userfg_shared_pair;
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

	/* 
	 * Shared memory management:
	 * non-POD C++ objects canot be shared.
	 * KISS: Share only a single ip=>user and a single user=>fg pair 
	 * at a time to avoid implementing our own (inefficient) lookup 
	 * algorithm.
	 *
	 */

	int fd;
	
	fd = shm_open(
		"dg_shared_ipuser_pair",
		O_RDWR | O_CREAT,
		0666
	);
	ftruncate(fd, sizeof(ipuser_POD_pair)); 
	ipuser_shared_pair = (ipuser_POD_pair *) mmap(
		0, sizeof(ipuser_POD_pair), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0
	);

	fd = shm_open(
		"dg_shared_userfg_pair",
		O_RDWR | O_CREAT,
		0666
	);
	ftruncate(fd, sizeof(userfg_POD_pair));
	userfg_shared_pair = (userfg_POD_pair *) mmap(
		0, sizeof(userfg_POD_pair), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0
	);

	strcpy(ipuser_shared_pair->ip, "0.0.0.0");
	strcpy(ipuser_shared_pair->user, "__nobody__");
	strcpy(userfg_shared_pair->user, "__nobody__");
	userfg_shared_pair->fg   = 0;

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

	// put the shared pair into the cache
	std::string shared_ipstring(ipuser_shared_pair->ip);
	std::string shared_username(ipuser_shared_pair->user);
	ipuser_cache[shared_ipstring] = shared_username;

	if (ipuser_cache.count(ipstring)) { 
		string = ipuser_cache[ipstring];
		return DGAUTH_OK;
	} 
	
	// query the db
	String sql_query( cv["sqlauthipuserquery"] );
	sql_query.replaceall("-IPADDRESS-", ipstring.c_str());
	try {
		std::cout << time(NULL) << ":" << sql_query << std::endl; // DEBUG
		soci::session sql(cv["sqlauthdb"], connection_string);
		soci::indicator ind;
		sql << sql_query, soci::into(string, ind);
		if ( ind == soci::i_ok ) {
			// put the result in per-process cache
			ipuser_cache[ipstring] = string;
			// and in the shared pair
			strcpy(ipuser_shared_pair->ip, ipstring.c_str());
			strcpy(ipuser_shared_pair->user, string.c_str());
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

	// put the shared pair into the cache
	std::string shared_user_cppstr(userfg_shared_pair->user); 
	userfg_cache[shared_user_cppstr] = userfg_shared_pair->fg;

	if (userfg_cache.count(user)) {
		fg = userfg_cache[user];
		return DGAUTH_OK;
	}		

	// query the db
	String sql_query( cv["sqlauthusergroupquery"] );
	sql_query.replaceall("-USERNAME-", user.c_str());
	std::vector<std::string> sqlgroups(32); // will be shrinked
	try {
		std::cout << time(NULL) << ":" << sql_query << std::endl; // DEBUG
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
					// put the result in the per-process cache
					userfg_cache[user] = fg;
					// and in the shared pair
					strcpy(userfg_shared_pair->user, user.c_str());
					userfg_shared_pair->fg = fg;
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
