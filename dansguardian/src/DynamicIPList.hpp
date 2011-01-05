// DynamicIPList - maintains a sorted list of IP addresses, for checking &
// limiting the number of concurrent proxy users.

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

#ifndef __HPP_DYNAMICIPLIST
#define __HPP_DYNAMICIPLIST


// DECLARATIONS

class DynamicIPList {
public:
	DynamicIPList(int maxitems, int maxitemage);
	~DynamicIPList();

#ifdef DGDEBUG
	int getListSize() { return size; };
#endif
	int getNumberOfItems() { return items; };

	// return whether or not given IP is in/could be added to list
	// (i.e. returns false if list already full & this IP's not in it)
	bool inList(unsigned long int ip);

	// remove entries older than maxage
	void purgeOldEntries();

private:
	// IPs and their ages
	unsigned long int *data;
	unsigned long int *datatime;
	
	// list size; no. of items currently in list; max. allowed item age
	int size;
	int items;
	int maxage;
	
	void stamp(unsigned int pos);
	
	// binary search for given ip
	int search(int a, int s, unsigned long int ip);
	
	// compacts list removing blanks
	void empties();
	
	// returns position of given IP in list, or (0-pos)-1 where pos is where
	// IP should be inserted to retain sorting.
	int posInList(unsigned long int ip);
};

#endif
