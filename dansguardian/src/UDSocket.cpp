// UDSocket class - implements BaseSocket for UNIX domain sockets

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
#include "UDSocket.hpp"

#include <syslog.h>
#include <csignal>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <stdexcept>
#include <stddef.h>

#ifdef DGDEBUG
#include <iostream>
#endif

// necessary for calculating size of sockaddr_un in a portable manner

#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((size_t) &((TYPE *) 0)->MEMBER)
#endif

// IMPLEMENTATION

// constructor - creates default UNIX domain socket & clears address structs
UDSocket::UDSocket()
{
	sck = socket(PF_UNIX, SOCK_STREAM, 0);
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sun_family = AF_UNIX;
	peer_adr.sun_family = AF_UNIX;
}

// create socket from pre-existing FD (address structs will be invalid!)
UDSocket::UDSocket(int fd):BaseSocket(fd)
{
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sun_family = AF_UNIX;
	peer_adr.sun_family = AF_UNIX;
}

// create socket from given FD & local address (checkme: is it local or remote that gets passed in here?)
UDSocket::UDSocket(int newfd, struct sockaddr_un myadr):BaseSocket(newfd)
{
	my_adr = myadr;
	my_adr_length = sizeof(my_adr.sun_family) + strlen(my_adr.sun_path);
}

// close socket & clear address structs
void UDSocket::reset()
{
	this->baseReset();
	sck = socket(PF_UNIX, SOCK_STREAM, 0);
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sun_family = AF_UNIX;
	peer_adr.sun_family = AF_UNIX;
}

// accept incoming connection & return new UDSocket
UDSocket* UDSocket::accept()
{
	my_adr_length = sizeof(my_adr.sun_family) + strlen(my_adr.sun_path);
	int newfd = this->baseAccept((struct sockaddr*) &my_adr, &my_adr_length);
	UDSocket* s = new UDSocket(newfd, my_adr);
	return s;
}

// connect to given server (following default constructor)
int UDSocket::connect(const char *path)
{
#ifdef DGDEBUG
	std::cout << "uds connect:" << path << std::endl;
#endif
	strcpy(my_adr.sun_path, path);

	my_adr_length = offsetof(struct sockaddr_un, sun_path) + strlen(path);

	return ::connect(sck, (struct sockaddr *) &my_adr, my_adr_length);
}

// bind socket to given path
int UDSocket::bind(const char *path)
{				// to bind a unix domain socket to a path
	unlink(path);
	strcpy(my_adr.sun_path, path);

	my_adr_length = offsetof(struct sockaddr_un, sun_path) + strlen(path);

	return ::bind(sck, (struct sockaddr *) &my_adr, my_adr_length);
}
