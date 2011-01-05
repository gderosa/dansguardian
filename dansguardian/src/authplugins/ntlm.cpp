// NTLM auth plugin

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


// INCLUDES
#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../Auth.hpp"
#include "../FDTunnel.hpp"
#include "../OptionContainer.hpp"

#include <syslog.h>

#include <iconv.h>


// DEFINES

extern OptionContainer o;

// NTLM username grabbing needs to be independent of endianness

#ifdef HAVE_BYTESWAP_H
# include <byteswap.h>
# define bswap16(x) bswap_16(x)
# define bswap32(x) bswap_32(x)
#else
# ifndef bswap16
#  define bswap16(x) (((((u_int16_t)x) >> 8) & 0xff) | ((((u_int16_t)x) & 0xff) << 8))
# endif
# ifndef bswap32
#  define bswap32(x) (((((u_int32_t)x) & 0xff000000) >> 24) | ((((u_int32_t)x) & 0x00ff0000) >>  8) | \
	((((u_int32_t)x) & 0x0000ff00) <<  8) | ((((u_int32_t)x) & 0x000000ff) << 24))
# endif
#endif

#ifdef WORDS_BIGENDIAN
# define SSWAP(x) (bswap16((x)))
# define WSWAP(x) (bswap32((x)))
#else
# define SSWAP(x) (x)
# define WSWAP(x) (x)
#endif


// DECLARATIONS

// class name is relevant!
class ntlminstance:public AuthPlugin
{
public:
	// keep credentials for all requests on a given persistent connection;
	// NTLM proxy auth is designed to be used in this manner and won't re-send credentials.
	ntlminstance(ConfigVar &definition):AuthPlugin(definition) { is_connection_based = true; needs_proxy_query = true; };

	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);
};

// things need to be on byte boundaries here
#pragma pack(1)
struct strhdr {
	int16_t len;
	int16_t maxlen;
	int32_t offset;
};

struct ntlmhdr {
	char signature[8]; // literally NTLMSSP\0
	int32_t type;      // 1, 2 or 3, auth resposes are type 3.
};

// this struct is only valid if h.type == 3
// as we only evesdrop to get userid dont care about type 1 and 2 messages
struct ntlm_auth {
	ntlmhdr h;
	strhdr lmresponse;          // LANMAN challenge response
	strhdr ntresponse;          // NT challenge response
	strhdr domain;              // Domain to authenticate against
	strhdr user;                // Username (only thing we care about atm.)
	strhdr workstation;         // Workstation name
	strhdr sessionkey;          // Session key for server's use
	int32_t flags;              // Request flags
	char payload[256 * 6];      // String data - enough for everything at 255 chars
	                            // but packet does not need to be that big
};

// union so load data into buffer and the byte aligned struct gets
// filled in.
union ntlm_authenticate {
	ntlm_auth a;
	char buf[sizeof(ntlm_auth)];
};
#pragma pack()

// "template adaptor" for iconv - basically, let G++ do the hard work of
// figuring out whether or not the second parameter is const for us ;)
template <typename T>
inline size_t local_iconv_adaptor (size_t (*iconv_func)(iconv_t, T, size_t *, char**,size_t*),
	iconv_t cd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft)
{
  return iconv_func (cd, (T)inbuf, inbytesleft, outbuf, outbytesleft);
}


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *ntlmcreate(ConfigVar & definition)
{
	return new ntlminstance(definition);
}

// end of Class factory

// ntlm auth header username extraction - also lets connection persist long enough to complete NTLM negotiation
int ntlminstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string)
{
	FDTunnel fdt;

	String at(h.getAuthType());
	if (at != "NTLM") {
		// if no auth currently underway, then...
		if (at.length() == 0) {
			// allow the initial request through so the client will get the proxy's initial auth required response.
			// advertise persistent connections so that parent proxy will agree to advertise NTLM support.
#ifdef DGDEBUG
			std::cout << "No auth negotiation currently in progress - making initial request persistent so that proxy will advertise NTLM" << std::endl;
#endif

			h.makePersistent();
		}
		return DGAUTH_NOMATCH;
	}

#ifdef DGDEBUG
	std::cout << "NTLM - sending step 1" << std::endl;
#endif
	if (o.forwarded_for) {
		std::string clientip;
		if (o.use_xforwardedfor) {
			// grab the X-Forwarded-For IP if available
			clientip = h.getXForwardedForIP();
			// otherwise, grab the IP directly from the client connection
			if (clientip.length() == 0)
				clientip = peercon.getPeerIP();
		} else {
			clientip = peercon.getPeerIP();
		}
		h.addXForwardedFor(clientip);  // add squid-like entry
	}
	h.makePersistent();
	h.out(&peercon, &proxycon, __DGHEADER_SENDALL);
#ifdef DGDEBUG
	std::cout << "NTLM - receiving step 2" << std::endl;
#endif
	h.in(&proxycon, true);

	if (h.authRequired()) {
#ifdef DGDEBUG
		std::cout << "NTLM - sending step 2" << std::endl;
#endif
		h.out(NULL, &peercon, __DGHEADER_SENDALL);
		if (h.contentLength() != -1)
			fdt.tunnel(proxycon, peercon, false, h.contentLength(), true);
#ifdef DGDEBUG
		std::cout << "NTLM - receiving step 3" << std::endl;
#endif
		h.in(&peercon, true);

#ifdef DGDEBUG
		std::cout << "NTLM - decoding type 3 message" << std::endl;
#endif

		std::string message(h.getAuthData());

		ntlm_authenticate auth;
		ntlm_auth *a = &(auth.a);
		static char username[256]; // fixed size
		static char username2[256];
		char* inptr = username;
		char* outptr = username2;
		size_t l,o;

		// copy the NTLM message into the union's buffer, simultaneously filling in the struct
		if ((message.length() > sizeof(ntlm_auth)) || (message.length() < offsetof(ntlm_auth, payload))) {
			syslog(LOG_ERR, "NTLM - Invalid message of length %zd, message was: %s", message.length(), message.c_str());
#ifdef DGDEBUG
			std::cerr << "NTLM - Invalid message of length " << message.length() << ", message was: " << message << std::endl;
#endif
			return -3;
		}
		memcpy((void *)auth.buf, (const void *)message.c_str(), message.length());

		// verify that the message is indeed a type 3
		if (strcmp("NTLMSSP",a->h.signature) == 0 && WSWAP(a->h.type) == 3) {
			// grab the length & offset of the username within the message
			// cope with the possibility we are a different byte order to Windows
			l = SSWAP(a->user.len);
			o = WSWAP(a->user.offset);

			if ((l > 0) && (o >= 0) && (o + l) <= sizeof(a->payload) && (l <= 254)) {
				// everything is in range
				// note offsets are from start of packet - not the start of the payload area
				memcpy((void *)username, (const void *)&(auth.buf[o]),l);
				username[l] = '\0';
				// check flags - we may need to convert from UTF-16 to something more sensible
				int f = WSWAP(a->flags);
				if (f & WSWAP(0x0001)) {
					iconv_t ic = iconv_open("UTF-8", "UTF-16LE");
					if (ic == (iconv_t)-1) {
						syslog(LOG_ERR, "NTLM - Cannot initialise conversion from UTF-16LE to UTF-8: %s", strerror(errno));
#ifdef DGDEBUG
						std::cerr << "NTLM - Cannot initialise conversion from UTF-16LE to UTF-8: " << strerror(errno) << std::endl;
#endif
						iconv_close(ic);
						return -2;
					}
					size_t l2 = 256;
					local_iconv_adaptor(iconv, ic, &inptr, &l, &outptr, &l2);
					iconv_close(ic);
					username2[256 - l2] = '\0';
#ifdef DGDEBUG
					std::cout << "NTLM - got username (converted from UTF-16LE) " << username2 << std::endl;
#endif
					string = username2;
				} else {
#ifdef DGDEBUG
					std::cout << "NTLM - got username " << username << std::endl;
#endif
					string = username;
				}
				return DGAUTH_OK;
			}
		}
		return DGAUTH_NOMATCH;
	} else {
#ifdef DGDEBUG
		for (unsigned int i = 0; i < h.header.size(); i++)
			std::cout << h.header[i] << std::endl;
#endif
		return -1;
	}
}
