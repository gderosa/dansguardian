// IP SQL auth plugin

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.

//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


// INCLUDES
#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../Auth.hpp"
#include "../RegExp.hpp"
#include "../OptionContainer.hpp"

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
/*
private:
	std::vector<ip> iplist;
	std::list<subnetstruct> ipsubnetlist;
	std::list<rangestruct> iprangelist;

	int readIPMelangeList(const char *filename);
	int searchList(int a, int s, const uint32_t &ip);
	int inList(const uint32_t &ip);
	int inSubnet(const uint32_t &ip);
	int inRange(const uint32_t &ip);
*/
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
  return 0;
}

// filter group determination
// never actually return NOUSER from this, because we don't actually look in the filtergroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int sqlauthinstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string)
{
  // we don't get usernames out of this plugin, just a filter group
  // for now, use the IP as the username

  if (o.use_xforwardedfor) {
    // grab the X-Forwarded-For IP if available
    string = h.getXForwardedForIP();
    // otherwise, grab the IP directly from the client connection
    if (string.length() == 0)
      string = peercon.getPeerIP();
  } else {
    string = peercon.getPeerIP();
  }
  return DGAUTH_OK;

}

int sqlauthinstance::determineGroup(std::string &user, int &fg)
{
	fg = 1;
	return DGAUTH_OK;
}


