#include <ctime>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#include <string>
#include <fstream>
#include <sstream>

// stores key-value pairs with timestamps
template <class KeyType, class ValueType>
class SharedCache 
{
public:
	SharedCache(std::string const& filename_); 
	~SharedCache(); 
	std::string filename;
	bool store(std::pair <KeyType, ValueType> const& pair);
protected:
	bool file_exists(std::string const& filename_);
	bool file_exists();
	bool update(std::pair <KeyType, ValueType> const& pair);
	bool append_row(
	std::ofstream const& of, std::pair <KeyType, ValueType> const& pair);
};

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
bool SharedCache<KeyType, ValueType>::update(
		std::pair <KeyType, ValueType> const& pair
)
{
	return true;
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
	ifstream ifs;
	ofstream ofs;
	ofstream oflocks;
	oflocks.open(strcat(filename.c_str(), ".lock"));
	ifs.open(filename);
	ofs.open(strcat(filename.c_str(), ".new"));
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


