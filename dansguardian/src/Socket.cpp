// Socket class - implements BaseSocket for INET domain sockets

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
#include "Socket.hpp"

#include <syslog.h>
#include <csignal>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <stdexcept>
#include <netinet/tcp.h>


// IMPLEMENTATION

// constructor - create an INET socket & clear address structs
Socket::Socket()
{
	sck = socket(AF_INET, SOCK_STREAM, 0);
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sin_family = AF_INET;
	peer_adr.sin_family = AF_INET;
	peer_adr_length = sizeof(struct sockaddr_in);
	int f = 1;
	setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));
}

// create socket from pre-existing FD (address structs will be invalid!)
Socket::Socket(int fd):BaseSocket(fd)
{
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sin_family = AF_INET;
	peer_adr.sin_family = AF_INET;
	peer_adr_length = sizeof(struct sockaddr_in);
	int f = 1;
	setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));
}

// create socket from pre-existing FD, storing local & remote IPs
Socket::Socket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip):BaseSocket(newfd)
{
	memset(&my_adr, 0, sizeof my_adr);  // ***
	memset(&peer_adr, 0, sizeof peer_adr);  // ***
	my_adr.sin_family = AF_INET;  // *** Fix suggested by
	peer_adr.sin_family = AF_INET;  // *** Christopher Weimann
	my_adr = myip;
	peer_adr = peerip;
	peer_adr_length = sizeof(struct sockaddr_in);
	int f = 1;
	setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));
}

// find the ip to which the client has connected
std::string Socket::getLocalIP()
{
	return inet_ntoa(my_adr.sin_addr);
}

// find the ip of the client connecting to us
std::string Socket::getPeerIP()
{
	return inet_ntoa(peer_adr.sin_addr);
}

// find the port of the client connecting to us
int Socket::getPeerSourcePort()
{
	return ntohs(peer_adr.sin_port);
}

// return the address of the client connecting to us
unsigned long int Socket::getPeerSourceAddr()
{
	return (unsigned long int)ntohl(peer_adr.sin_addr.s_addr);
}

// close connection & wipe address structs
void Socket::reset()
{
	this->baseReset();
	sck = socket(AF_INET, SOCK_STREAM, 0);
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sin_family = AF_INET;
	peer_adr.sin_family = AF_INET;
	peer_adr_length = sizeof(struct sockaddr_in);
}

// connect to given IP & port (following default constructor)
int Socket::connect(const std::string &ip, int port)
{
	int len = sizeof my_adr;
	peer_adr.sin_port = htons(port);
	inet_aton(ip.c_str(), &peer_adr.sin_addr);
	return ::connect(sck, (struct sockaddr *) &peer_adr, len);
}
// bind socket to given port
int Socket::bind(int port)
{
	int len = sizeof my_adr;
	int i = 1;
	setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	my_adr.sin_port = htons(port);
	return ::bind(sck, (struct sockaddr *) &my_adr, len);
}

// bind socket to given port & IP
int Socket::bind(const std::string &ip, int port)
{
	int len = sizeof my_adr;
	int i = 1;
	setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	my_adr.sin_port = htons(port);
	my_adr.sin_addr.s_addr = inet_addr(ip.c_str());
	return ::bind(sck, (struct sockaddr *) &my_adr, len);
}

// accept incoming connections & return new Socket
Socket* Socket::accept()
{
	peer_adr_length = sizeof(struct sockaddr_in);
	int newfd = this->baseAccept((struct sockaddr*) &peer_adr, &peer_adr_length);
	Socket* s = new Socket(newfd, my_adr, peer_adr);
	return s;
}
