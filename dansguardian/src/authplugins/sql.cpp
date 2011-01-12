// IP SQL auth plugin

// Please refer to http://dansguardian.org/?page=copyright2
// for the license for this code.

//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA	02111-1307	USA


// INCLUDES
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

#include <soci/soci.h>


// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;

// class name is relevant!
class sqlauthinstance:public AuthPlugin
{
public:
	// keep credentials for the whole of a connection - IP isn't going to change.
	// not quite true - what about downstream proxy with x-forwarded-for?
	sqlauthinstance(ConfigVar &definition):AuthPlugin(definition)
	{
		if (!o.use_xforwardedfor)
			is_connection_based = true;
	};

	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);
	int determineGroup(std::string &user, int &fg);

	int init(void* args);
	int quit();
private:
	soci::session sql;
	bool connected;
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *sqlauthcreate(ConfigVar & definition)
{
	return new sqlauthinstance(definition);
}

// end of Class factory

// 
//
// Standard plugin funcs
//
//

// plugin quit - clear IP, subnet & range lists
int sqlauthinstance::quit() {
	/*
	iplist.clear();
	ipsubnetlist.clear();
	iprangelist.clear();
	*/
	return 0;
}

// plugin init 
int sqlauthinstance::init(void* args) {
	connected = false;
	char connection_string[1024];
	sprintf(connection_string, "host='%s' db='%s' user='%s' password='%s'", 
		cv["sqlauthdbhost"].c_str(), 
		cv["sqlauthdbname"].c_str(), 
		cv["sqlauthdbuser"].c_str(), 
		cv["sqlauthdbpass"].c_str()
	);
#ifdef DGDEBUG
	printf("sqlauth: %s connection string: %s\n", 
			cv["sqlauthdb"].c_str(), connection_string);
#endif
	try {
		sql.open(cv["sqlauthdb"], connection_string);
		connected = true;
		return 0;
	}
	catch (std::exception const &e) {
		if (!is_daemonised) 
			std::cerr << "sqlauth (" << cv["sqlauthdb"] << "): " << e.what() << '\n';
		syslog(LOG_ERR, e.what());
		return 1;
	}
}

int sqlauthinstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string)
{
	if(!connected) // so other plugins will be queried
			return DGAUTH_NOMATCH;

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
	
	String sql_query( cv["sqlauthipuserquery"] );
	sql_query.replaceall("-IPADDRESS-", ipstring.c_str());

#ifdef DGDEBUG
	std::cout << "sqlauthipuserquery expanded to: " 
		<< sql_query << std::endl;
#endif

	string = "sql_username";
	return DGAUTH_OK;
}

int sqlauthinstance::determineGroup(std::string &user, int &fg)
{
	fg = 1;
	return DGAUTH_OK;
}


