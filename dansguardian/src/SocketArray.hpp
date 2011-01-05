// SocketArray - wrapper for clean handling of an array of Sockets

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

#ifndef __HPP_SOCKETARRAY
#define __HPP_SOCKETARRAY


// INCLUDES
#include "Socket.hpp"
#include "String.hpp"

#include <deque>


// DECLARATIONS

class SocketArray
{
public:
	// set sensible defaults
	SocketArray():drawer(NULL),socknum(0) {};
	// delete all sockets
	~SocketArray();

	// close all old socks & create specified amount of new ones
	void reset(int sockcount);
	
	// just delete the lot of 'em
	void deleteAll();

	// bind our sockets to the given IPs
	int bindAll(std::deque<String> &ips, int port);
	// bind just the one, to all available IPs
	int bindSingle(int port);
	// set all sockets listening with given kernel queue length
	int listenAll(int queue);

	// shove all socket FDs into the given array (pass in unallocated)
	int* getFDAll();

	// array dereference operator
	Socket* operator[] (int i) { return &(drawer[i]); };

private:
	// our sock collection container
	Socket* drawer;
	// how many sockets we have
	unsigned int socknum;
};

#endif
