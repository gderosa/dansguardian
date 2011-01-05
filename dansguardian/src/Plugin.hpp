// the Plugin interface - inherit this to define new plugin types

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

#ifndef __HPP_PLUGIN
#define __HPP_PLUGIN


// INCLUDES


// DECLARATIONS

class Plugin
{
public:
	virtual ~Plugin(){};
	
	// plugin initialise/quit routines.
	// return 0 for OK, < 0 for error, > 0 for warning
	virtual int init(void* args) = 0;
	virtual int quit() = 0;
};

#endif
