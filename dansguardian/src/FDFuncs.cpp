//  File descriptor functions - generic functions for reading, writing,
//  and (in future) creating files
//  Please use *only* for files, not sockets!

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
#include "FDFuncs.hpp"


// IMPLEMENTATION

// wrapper around FD read that restarts on EINTR
int readEINTR(int fd, char *buf, unsigned int count)
{
	int rc;
	errno = 0;
	while (true) {		// using the while as a restart point with continue
		rc = read(fd, buf, count);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;  // was interupted by a signal so restart
			}
		}
		break;  // end the while
	}
	return rc;  // return status
}

// wrapper around FD write that restarts on EINTR
int writeEINTR(int fd, char *buf, unsigned int count)
{
	int rc;
	errno = 0;
	while (true) {		// using the while as a restart point with continue
		rc = write(fd, buf, count);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;  // was interupted by a signal so restart
			}
		}
		break;  // end the while
	}
	return rc;  // return status
}
