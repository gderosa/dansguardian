#include <ctime>
#include <cstdio>
#include <sys/stat.h>

// stores key-value pairs with timestamps
template <class KeyType, class ValueType>
class SharedCache
{
public:
	SharedCache(const std::string & filename_); 
	~SharedCache() {};
	std::string filename;
	bool store(const std::pair <KeyType, ValueType> pair);
protected:
	bool file_exists();
	update(const std::pair <KeyType, ValueType> pair);
	append_row(
		const std::ofstream & of, const std::pair <KeyType, ValueType> & pair);
}

SharedCache::SharedCache(const std::string & filename_){
	filename = filename_;
}

bool SharedCache::store(const std::pair <KeyType, ValueType> & pair) {
	if file_exists() {
		return update(std::pair <KeyType, ValueType> pair);
	} else {
		if file_exists(filename + ".lock")
			return false; // silently fail, don't wait
		std::ofstream f, flock;
		flock.open(filename + ".lock");
		f.open(filename);
		append_row(f, pair);
		f.close();
		flock.close();
		remove(filename + ".lock");
		return true;
	}
}


SharedCache::append_row(
	const std::ofstream &of, 
	const std::pair <KeyType, ValueType> pair
)
{
	of << 
		pair.first()  << ' '  << 
		pair.second() << ' '  << 
		time(NULL)    << '\n' ;  
}

bool SharedCache::file_exists(std::string filename_=filename) {
	struct stat st;
	return bool( stat(filename.c_str(), &st) ); 
}

