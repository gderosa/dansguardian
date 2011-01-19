#include <ctime>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#include <string>
#include <fstream>
#include <sstream>

#include "SharedCache.hpp"

template <class KeyType, class ValueType>
SharedCache<KeyType, ValueType>::SharedCache(std::string const& filename_){
	filename = filename_;
}

template <class KeyType, class ValueType>
bool SharedCache<KeyType, ValueType>::store(
		std::pair <KeyType, ValueType> const& pair
) 
{
	if (file_exists()) {
		return update(pair);
	} else {
		if (file_exists(filename + ".lock"))
			return false; // silently fail, don't wait
		std::ofstream f;
		std::ofstream flock;
		flock.open(strcat(filename.c_str(), ".lock"));
		f.open(filename.c_str());
		append_row(f, pair);
		f.close();
		flock.close();
		remove(strcat(filename.c_str(), ".lock"));
		return true;
	}
}

template <class KeyType, class ValueType>
bool SharedCache<KeyType, ValueType>::append_row(
	std::ofstream const& of, 
	std::pair <KeyType, ValueType> const& pair
)
{
	of << 
		pair.first()  << ' '  << 
		pair.second() << ' '  << 
		time(NULL)    << '\n' ;  
	return true;
}

template <class KeyType, class ValueType>
bool SharedCache<KeyType, ValueType>::update(
	std::pair <KeyType, ValueType> const& pair		
)
{
	std::ifstream ifs;
	std::ostringstream tmps;
	std::ofstream oflocks;
	oflocks.open(strcat(filename.c_str(), ".lock"));
	ifs.open(filename.c_str()); 
	char linebuf[1024];
	while( !ifs.getline(linebuf, 1024).eof() ) { 
		std::istringstream linestream(linebuf);
		KeyType key;
		ValueType value;
		time_t timestamp;
		linestream >> key >> value >> timestamp;
		if (key != pair.first()) 
			tmps << key << value << timestamp << '\n';
	}
	ifs.close();
	std::ofstream ofs;
	ofs.open(filename.c_str()); 
	ofs << tmps;
	ofs << 
		pair.first()  << ' '   << 
		pair.second() << ' '   << 
		time(NULL)    << '\n'  ;
	ofs.close();
	oflocks.close();
	remove(strcat(filename.c_str(), ".lock")); 
}

template <class KeyType, class ValueType>
bool SharedCache<KeyType, ValueType>::file_exists(
		std::string const& filename_
) 
{
	struct stat st;
	return bool( stat(filename_.c_str(), &st) ); 
}

template <class KeyType, class ValueType>
bool SharedCache<KeyType, ValueType>::file_exists() 
{
	return file_exists(filename);
}


