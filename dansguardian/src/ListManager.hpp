// ListManager - for creating & containing all ListContainers of item & phrase lists

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@/jadeb//.com).
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

#ifndef __HPP_LISTMANAGER
#define __HPP_LISTMANAGER


// INCLUDES

#include "String.hpp"
#include "ListContainer.hpp"

#include <deque>


// DECLARATION

class ListManager
{
public:
	// the lists we manage
	std::deque<ListContainer * > l;

	~ListManager();
	
	// create a new item list. re-uses existing lists if a reload is not necessary.
	// calls readItemList.
	int newItemList(const char *filename, bool startswith, int filters, bool parent);
	// create a new phrase list. re-uses existing lists, but cannot check nested lists (known limitation).
	// does not call readPhraseList. (checkme: why?)
	int newPhraseList(const char *exception, const char *banned, const char *weighted);

	bool readbplfile(const char *banned, const char *exception, const char *weighted, unsigned int &list, bool force_quick_search);
	
	void deRefList(size_t item);
	
	// delete lists with refcount zero
	void garbageCollect();

private:
	// find an empty slot in our collection of listcontainters
	int findNULL();
	
	void refList(size_t item);
};

#endif
