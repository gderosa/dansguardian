// Debug functions

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// DEFINES
#define BUFFSIZE 256

// INCLUDES
#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "Debug.hpp"

std::string ErrStr() {
	char msg[BUFFSIZE];

	strerror_r(errno, msg, BUFFSIZE);
	return std::string(msg);
}
