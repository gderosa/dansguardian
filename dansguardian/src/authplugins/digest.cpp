// Digest auth plugin 
// Based on contribution by Darryl Sutherland <darryl@weblink.co.za>

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

#include <syslog.h>


// DECLARATIONS

// class name is relevant!
class digestinstance:public AuthPlugin
{
public:
	digestinstance(ConfigVar &definition):AuthPlugin(definition) {};
	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *digestcreate(ConfigVar & definition)
{
	return new digestinstance(definition);
}

// end of Class factory

// proxy auth header username extraction
int digestinstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string)
{
	// don't match for non-digest auth types
	String t = h.getAuthType();
	t.toLower();
	if (t != "digest")
		return DGAUTH_NOMATCH;
	// extract username
	string = h.getRawAuthData();
	if (string.length() > 0) {
		String temp(string);
		temp = temp.after("username=\"");
		temp = temp.before("\"");
		string = temp;
		return DGAUTH_OK;
	}
	return DGAUTH_NOMATCH;
}
