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


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "Auth.hpp"
#include "OptionContainer.hpp"

#include <iostream>
#include <syslog.h>

// GLOBALS

extern OptionContainer o;
extern bool is_daemonised;

extern authcreate_t proxycreate;
extern authcreate_t digestcreate;
extern authcreate_t identcreate;
extern authcreate_t ipcreate;

#ifdef ENABLE_NTLM
extern authcreate_t ntlmcreate;
#endif

// IMPLEMENTATION

AuthPlugin::AuthPlugin(ConfigVar &definition):is_connection_based(false), needs_proxy_query(false)
{
	cv = definition;
}

int AuthPlugin::init(void *args)
{
	return 0;
}

int AuthPlugin::quit()
{
	return 0;
}

// determine what filter group the given username is in
// return -1 when user not found
int AuthPlugin::determineGroup(std::string &user, int &fg)
{
	if (user.length() < 1 || user == "-") {
		return DGAUTH_NOMATCH;
	}
	String u(user);
	u.toLower();  // since the filtergroupslist is read in in lowercase, we should do this.
	user = u.toCharArray();  // also pass back to ConnectionHandler, so appears lowercase in logs
	String ue(u);
	ue += "=";

	char *i = o.filter_groups_list.findStartsWithPartial(ue.toCharArray());

	if (i == NULL) {
#ifdef DGDEBUG
		std::cout << "User not in filter groups list: " << ue << std::endl;
#endif
		return DGAUTH_NOUSER;
	}
#ifdef DGDEBUG
	std::cout << "User found: " << i << std::endl;
#endif
	ue = i;
	if (ue.before("=") == u) {
		ue = ue.after("=filter");
		int l = ue.length();
		if (l < 1 || l > 2) {
			return DGAUTH_NOUSER;
		}
		fg = ue.toInteger();
		if (fg > o.numfg) {
			return DGAUTH_NOUSER;
		}
		if (fg > 0) {
			fg--;
		}
		return DGAUTH_OK;
	}
	return DGAUTH_NOUSER;
}

// take in a configuration file, find the AuthPlugin class associated with the plugname variable, and return an instance
AuthPlugin* auth_plugin_load(const char *pluginConfigPath)
{
	ConfigVar cv;

	if (cv.readVar(pluginConfigPath, "=") > 0) {
		if (!is_daemonised) {
			std::cerr << "Unable to load plugin config: " << pluginConfigPath << std::endl;
		}
		syslog(LOG_ERR, "Unable to load plugin config %s", pluginConfigPath);
		return NULL;
	}

	String plugname(cv["plugname"]);
	if (plugname.length() < 1) {
		if (!is_daemonised) {
			std::cerr << "Unable read plugin config plugname variable: " << pluginConfigPath << std::endl;
		}
		syslog(LOG_ERR, "Unable read plugin config plugname variable %s", pluginConfigPath);
		return NULL;
	}

	if (plugname == "proxy-basic") {
#ifdef DGDEBUG
		std::cout << "Enabling proxy-basic auth plugin" << std::endl;
#endif
		return proxycreate(cv);
	}

	if (plugname == "proxy-digest") {
#ifdef DGDEBUG
		std::cout << "Enabling proxy-digest auth plugin" << std::endl;
#endif
		return digestcreate(cv);
	}

	if (plugname == "ident") {
#ifdef DGDEBUG
		std::cout << "Enabling ident server auth plugin" << std::endl;
#endif
		return identcreate(cv);
	}

	if (plugname == "ip") {
#ifdef DGDEBUG
		std::cout << "Enabling IP-based auth plugin" << std::endl;
#endif
		return ipcreate(cv);
	}

#ifdef ENABLE_NTLM
	if (plugname == "proxy-ntlm") {
#ifdef DGDEBUG
		std::cout << "Enabling proxy-NTLM auth plugin" << std::endl;
#endif
		return ntlmcreate(cv);
	}
#endif

	if (!is_daemonised) {
		std::cerr << "Unable to load plugin: " << pluginConfigPath << std::endl;
	}
	syslog(LOG_ERR, "Unable to load plugin %s", pluginConfigPath);
	return NULL;
}
