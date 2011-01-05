//Defines the ConfigVar class, which implements reading options from a file
//into a map

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

#ifndef __HPP_CONFIGVAR
#define __HPP_CONFIGVAR


// INCLUDES
#include <cstring>
#include <map>
#include "String.hpp"


// DECLARATIONS
class ConfigVar
{
public:
	ConfigVar();

	// read the given file, splitting option/value at the given delimiter
	ConfigVar(const char *filename, const char *delimiter = "=");
	int readVar(const char *filename, const char *delimiter = "=");

	// return the value for the named option
	String entry(const char *reference);
	String operator[] (const char *reference);

private:
	// comparison operator (maps are sorted) - true if s1 comes before s2
	struct ltstr
	{
		bool operator() (String s1, String s2) const
		{
			return strcmp(s1.toCharArray(), s2.toCharArray()) < 0;
		}
	};

	// the map itself - key type, value type, key comparison operator
	std::map < String, String, ltstr > params;
};

#endif
