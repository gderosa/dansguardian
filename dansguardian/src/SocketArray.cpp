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


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "SocketArray.hpp"

#include <syslog.h>
#include <cerrno>


// GLOBALS

extern bool is_daemonised;


// IMPLEMENTATION

SocketArray::~SocketArray()
{
	delete[] drawer;
}

void SocketArray::deleteAll()
{
	delete[] drawer;
	drawer = NULL;
	socknum = 0;
}

// close all sockets & create new ones
void SocketArray::reset(int sockcount)
{
	delete[] drawer;
	
	drawer = new Socket[sockcount];
	socknum = sockcount;
}

// bind our first socket to any IP
int SocketArray::bindSingle(int port)
{
	if (socknum < 1) {
		return -1;
	}
	return drawer[0].bind(port);
}

// return an array of our socket FDs
int* SocketArray::getFDAll()
{
	int *fds = new int[socknum];
	for (unsigned int i = 0; i < socknum; i++) {
#ifdef DGDEBUG
		std::cerr << "Socket " << i << " fd:" << drawer[i].getFD() << std::endl;
#endif
		fds[i] = drawer[i].getFD();
	}
	return fds;
}

// listen on all IPs with given kernel queue size
int SocketArray::listenAll(int queue)
{
	for (unsigned int i = 0; i < socknum; i++) {
		if (drawer[i].listen(queue)) {
			if (!is_daemonised) {
				std::cerr << "Error listening to socket" << std::endl;
			}
			syslog(LOG_ERR, "%s","Error listening to socket");
			return -1;
		}
	}
	return 0;
}

// bind all sockets to given IP list
int SocketArray::bindAll(std::deque<String> &ips, int port)
{
	if (ips.size() > socknum) {
		return -1;
	}
	for (unsigned int i = 0; i < socknum; i++) {
#ifdef DGDEBUG
		std::cerr << "Binding server socket[" << port << " " << ips[i] << " " << i << "])" << std::endl;
#endif
		if (drawer[i].bind(ips[i].toCharArray(), port)) {
			if (!is_daemonised) {
				std::cerr << "Error binding server socket: ["
					<< port << " " << ips[i] << " " << i << "] (" << strerror(errno) << ")" << std::endl;
			}
			syslog(LOG_ERR, "Error binding socket: [%d %s %d] (%s)", port, ips[i].toCharArray(), i, strerror(errno));
			return -1;
		}
	}
	return 0;
}
