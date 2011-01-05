// This class is a generic multiplexing tunnel
// that uses blocking select() to be as efficient as possible.  It tunnels
// between the two supplied FDs.

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@//jadeb/.com).
//For support go to http://groups.yahoo.com/group/dansguardian

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

#ifndef __HPP_FDTUNNEL
#define __HPP_FDTUNNEL


// INCLUDES

#include "Socket.hpp"


// DECLARATIONS

// transparently forward data from one FD to another, i.e. tunnel between them
class FDTunnel
{
public:
	off_t throughput;  // used to log total data from from to to
	
	FDTunnel();
	
	// tunnel from fdfrom to fdto
	// return false if throughput larger than target throughput (for post upload size checking)
	bool tunnel(Socket &sockfrom, Socket &sockto, bool twoway = false, off_t targetthroughput = -1, bool ignore = false);

	void reset();
};

#endif
