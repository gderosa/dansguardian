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

#ifndef __HPP_SOCKET
#define __HPP_SOCKET


// INCLUDES

#include "BaseSocket.hpp"


// DECLARATIONS

class Socket : public BaseSocket
{
	friend class FDTunnel;
public:
	// create INET socket & clear address structs
	Socket();
	// create socket using pre-existing FD (address structs will be empty!)
	Socket(int fd);
	// create socket from pre-existing FD, storing given local & remote IPs
	Socket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip);
	
	// connect to given IP & port (following default constructor)
	int connect(const std::string& ip, int port);
	
	// bind to given port
	int bind(int port);
	// bind to given IP & port, for machines with multiple NICs
	int bind(const std::string& ip, int port);

	// accept incoming connections & return new Socket
	Socket* accept();
	
	// close socket & clear address structs
	void reset();

	// get remote IP/port
	std::string getPeerIP();
	int getPeerSourcePort();
	unsigned long int getPeerSourceAddr();
	
	// get local IP
	std::string getLocalIP();

private:
	// local & remote addresses
	struct sockaddr_in my_adr;
	struct sockaddr_in peer_adr;
};

#endif
