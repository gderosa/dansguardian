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


