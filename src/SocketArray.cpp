// SocketArray - wrapper for clean handling of an array of Sockets

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "SocketArray.hpp"

#include <string.h>
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
int SocketArray::bindAll(std::deque<String> &ips, std::deque<String> &ports)
{
	if (ips.size() > socknum) {
		return -1;
	}
	for (unsigned int i = 0; i < socknum; i++) {
#ifdef DGDEBUG
		std::cerr << "Binding server socket[" << ports[i] << " " << ips[i] << " " << i << "])" << std::endl;
#endif
		if (drawer[i].bind(ips[i].toCharArray(), ports[i].toInteger())) {
			if (!is_daemonised) {
				std::cerr << "Error binding server socket: ["
					<< ports[i] << " " << ips[i] << " " << i << "] (" << ErrStr() << ")" << std::endl;
			}
			syslog(LOG_ERR, "Error binding socket: [%s %s %d] (%s)", ports[i].toCharArray(), ips[i].toCharArray(), i, ErrStr().c_str());
			return -1;
		}
	}
	return 0;
}

