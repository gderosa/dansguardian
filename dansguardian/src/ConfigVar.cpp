//Implements the ConfigVar class

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
#include "ConfigVar.hpp"

#include <fstream>


// IMPLEMENTATION

// constructor
ConfigVar::ConfigVar()
{
}

// construct & read in the given config file
ConfigVar::ConfigVar(const char *filename, const char *delimiter)
{
	readVar(filename, delimiter);
}

// return the value for the named option
String ConfigVar::entry(const char *reference)
{
	return params[reference];
}

// same as above, but in handy operator form
String ConfigVar::operator[] (const char *reference)
{
	return params[reference];
}

// read in options from the given file, splitting option/value at delimiter
int ConfigVar::readVar(const char *filename, const char *delimiter)
{
	std::ifstream input(filename);
	char buffer[2048];

	params.clear();

	if (!input)
		return 1;

	while (input.getline(buffer, sizeof(buffer))) {

		char *command = strtok(buffer, delimiter);
		if (!command)
			continue;

		char *parameter = strtok(NULL, delimiter);
		if (!parameter)
			continue;

		// strip delimiters
		while (*parameter == '"' || *parameter == '\'' || *parameter == ' ')
			parameter++;
		int offset = strlen(parameter) - 1;

		while (parameter[offset] == '"' || parameter[offset] == '\'')
			parameter[offset--] = '\0';

		offset = strlen(command) - 1;
		while (command[offset] == ' ')
			command[offset--] = '\0';

		params[command] = parameter;
	}

	input.close();
	return 0;
}
