// AuthPlugin class - interface for plugins for retrieving client usernames
// and filter group membership

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@//jadeb.com).
//For support go to http://groups.yahoo.com/group/dansguardian

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

#ifndef __HPP_AUTH
#define __HPP_AUTH


// INCLUDES

#include "Plugin.hpp"
#include "ConfigVar.hpp"
#include "HTTPHeader.hpp"


// DEFINES

// success
#define DGAUTH_OK 0

// auth info required for this method not found (continue querying other plugins)
#define DGAUTH_NOMATCH 2

// auth info found, but no such user in filtergroupslist (stop querying plugins - use this code with caution!)
#define DGAUTH_NOUSER 3

// redirect the user to a login page
#define DGAUTH_REDIRECT 4

// any < 0 return code signifies error


// DECLARATIONS

class AuthPlugin:public Plugin
{
public:
	AuthPlugin(ConfigVar &definition);
	
	virtual int init(void* args);
	virtual int quit();

	// determine the username
	// return one of these codes:
	// OK - success, username in string
	// REDIRECT - redirect user to URL in string
	// NOMATCH - did not find the necessary info in the request (query remaining plugins)
	// any < 0 - error
	virtual int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string) = 0;	

	// determine what filter group the given username is in
	// queries the standard filtergroupslist
	// return one of these codes:
	// OK - success, group no. in fg
	// NOMATCH - did not find a group for this user (query remaining plugins)
	// NOUSER - did not find a group for this user (do not query remaining plugins)
	// any < 0 - error
	virtual int determineGroup(std::string &user, int &fg);

	// is this a connection-based auth type, i.e. assume all subsequent requests on the pconn are from the same user?
	bool is_connection_based;

	// does this auth type rely on queries from the parent proxy (e.g. NTLM, basic auth)?
	bool needs_proxy_query; 

protected:
	ConfigVar cv;
};

// class factory functions for Auth plugins
typedef AuthPlugin* authcreate_t(ConfigVar &);

// Return an instance of the plugin defined in the given configuration file
AuthPlugin* auth_plugin_load(const char *pluginConfigPath);

#endif
