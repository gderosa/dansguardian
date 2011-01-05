//Please refer to http://dansguardian.org/?page=copyright2
//
//for the license for this code.
//Written by Daniel Barron (daniel@jadeb.com).
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

#ifndef __HPP_IPLIST
#define __HPP_IPLIST


// INCLUDES

#include <list>


// DECLARATIONS

// convenience structs for subnets and IP ranges
struct ipl_subnetstruct {
	uint32_t maskedaddr;
	uint32_t mask;
};

struct ipl_rangestruct {
	uint32_t startaddr;
	uint32_t endaddr;
};

// IP subnet/range/mask & hostname list
class IPList
{
	public:
		void reset();
		bool inList(const std::string &ipstr, std::string *&host) const;
		bool readIPMelangeList(const char *filename);
	private:
		std::vector<uint32_t> iplist;
		std::vector<String> hostlist;
		std::list<ipl_rangestruct> iprangelist;
		std::list<ipl_subnetstruct> ipsubnetlist;
};

#endif
