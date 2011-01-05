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

#ifndef __HPP_UDSOCKET
#define __HPP_UDSOCKET


// INCLUDES

#include "BaseSocket.hpp"


// DECLARATIONS

class UDSocket : public BaseSocket
{
public:
	// create default UNIX domain socket & clear address structs
	UDSocket();
	// create socket from pre-existing FD (address structs will be empty!)
	UDSocket(int fd);
	// create socket from FD & local path (checkme: is it actually local that gets passed?)
	UDSocket(int newfd, struct sockaddr_un myadr);
	
	// connect socket to given server (following default constructor)
	int connect(const char *path);
	// bind socket to given path (for creating servers)
	int bind(const char *path);
	
	// accept incoming connection & return new UDSocket
	UDSocket* accept();
	
	// close connection & clear address structs
	void reset();

private:
	// local & remote address structs
	struct sockaddr_un my_adr;
	struct sockaddr_un peer_adr;
	socklen_t my_adr_length;
};

#endif
