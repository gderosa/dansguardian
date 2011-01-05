//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
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

// TODO: Download managers & DataBuffer should probably use this instead of
// being a mish-mash of copy-and-pasted inter-dependent code.
//
// If this were to use mmap() to map its temp files into memory, then we
// could use it for storage of *all* stuff needing filtering.

#ifndef __HPP_BACKEDSTORE
#define __HPP_BACKEDSTORE

// Class into which data can be liberally shoved into RAM up to threshold
// A, then automagically stored on disk instead up to threshold B, then
// start failing (but with sensible errors).
class BackedStore
{
public:
	// Constructor - pass in RAM & disk thresholds
	// and a directory path for temp files
	BackedStore(size_t _ramsize, size_t _disksize,
		const char *_tempdir = "/tmp");
	~BackedStore();

	// Add data to the store - returns false if
	// disksize would be exceeded or store has
	// been finalised
	bool append(const char *data, size_t len);

	// Finalise the store - cannot append any more
	// data after this.  Needed because if we are
	// writing to a temp file, mmap is used to access
	// the data, which requires a known file length.
	void finalise();

	// Data access
	const char *getData() const;

	// Get length of buffer
	size_t getLength() const;

	// Store the contents of the buffer using the given
	// prefix to generate a unique filename.  Return the filename.
	std::string store(const char *prefix);

private:
	// Buffer & file descriptor for in-memory/on-disk storage
	std::vector<char> rambuf;
	int fd;

	// Size of buffer/file
	size_t length;

	// Temp file name
	char *filename;

	// Thresholds
	size_t ramsize;
	size_t disksize;

	// Temp directory path
	std::string tempdir;

	// Pointer to mmapped file contents
	void *map;
};

#endif
