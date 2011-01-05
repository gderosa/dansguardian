//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@?? jadeb.com).
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

#ifndef __HPP_SYSV
#define __HPP_SYSV


// INCLUDES

#include "OptionContainer.hpp"

#include <sys/types.h>
#include <string>


// DECLARATIONS

// Kill the process specified in the given pidfile, optionally deleting the pidfile while we're at it,
// along with the UNIX domain sockets for the old logger & url cache
int sysv_kill(std::string pidfile, bool dounlink = true);

// show PID of running DG process
int sysv_showpid(std::string pidfile);
// check that the process in the pidfile is running
bool sysv_amirunning(std::string pidfile);

// delete any existing file with this name, and create a new one with relevant mode flags
int sysv_openpidfile(std::string pidfile);
// write our pid to the given file & close it
int sysv_writepidfile(int pidfilefd);

// send HUP or USR1 to the process in the pidfile
int sysv_hup(std::string pidfile);
int sysv_usr1(std::string pidfile);

#endif
