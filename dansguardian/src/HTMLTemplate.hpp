//Declares the HTMLTemplate class, for displaying template-based banned pages to clients

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

#ifndef __HPP_HTMLTEMPLATE
#define __HPP_HTMLTEMPLATE


// INCLUDES

#include "String.hpp"
#include "Socket.hpp"

#include <deque>
#include <string>


// DECLARATIONS

class HTMLTemplate
{
public:
	// string list for holding the template
	// public so that it can be accessed directly for display without using
	// the default set of placeholders
	std::deque<String> html;

	// wipe the loaded template
	void reset();

	// load in a template from the given file, looking for placeholder strings (reason, URL, category etc.)
	// optionally, provide your own set of placeholders
	bool readTemplateFile(const char *filename, const char *placeholders = NULL);
	
	// fill in the template with the given info and send it to the client over the given socket
	// only useful if you used the default set of placeholders
	void display(Socket *s, String *url, std::string &reason, std::string &logreason, std::string &categories,
		std::string *user, std::string *ip, std::string *host, int filtergroup, String &hashed);

private:
	// add a string to the list
	void push(String s);
};

#endif
