// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_CONNECTIONHANDLER
#define __HPP_CONNECTIONHANDLER


// INCLUDES
#include <iostream>
#include <string>
#include "OptionContainer.hpp"
#include "Socket.hpp"
#include "HTTPHeader.hpp"
#include "NaughtyFilter.hpp"


// DECLARATIONS

// check the URL cache to see if we've already flagged an address as clean
bool wasClean(String &url, const int fg);
// add a known clean URL to the cache
void addToClean(String &url, const int fg);

// record for storing information about POST data parts
// used for building up the POST data log column
struct postinfo
{
	// MIME type & original filename (if available)
	std::string mimetype;
	std::string filename;
	// name of file containing headers & body info
	// for this POST part (if it has been stored)
	std::string storedname;
	// size of part
	size_t size;
	// offset of body data from start of file
	// (if post part was stored on disk)
	size_t bodyoffset;
	bool blocked;
	postinfo():size(0), bodyoffset(0), blocked(false) {};
};

// the ConnectionHandler class - handles filtering, scanning, and blocking of
// data passed between a client and the external proxy.
class ConnectionHandler
{
public:
	ConnectionHandler():clienthost(NULL) {};
	~ConnectionHandler() { delete clienthost; };

	// pass data between proxy and client, filtering as we go.
	void handlePeer(Socket &peerconn, String &ip);
private:
	int filtergroup;
	bool matchedip;
	bool persistent_authed;

	std::string clientuser;
	std::string *clienthost;
	std::string urlparams;
	std::list<postinfo> postparts;

	void handleConnection(Socket &peerconn, String &ip);

	// write a log entry containing the given data (if required)
	void doLog(std::string &who, std::string &from, String &where, unsigned int &port,
		std::string &what, String &how, off_t &size, std::string *cat, bool isnaughty, int naughtytype,
		bool isexception, bool istext, struct timeval *thestart, bool cachehit, int code,
		std::string &mimetype, bool wasinfected, bool wasscanned, int naughtiness, int filtergroup,
		HTTPHeader* reqheader, bool contentmodified = false,
		bool urlmodified = false, bool headermodified = false);

	// perform URL encoding on a string
	std::string miniURLEncode(const char *s);

	// when using IP address counting - have we got any remaining free IPs?
	bool gotIPs(std::string ipstr);

	// check the request header is OK (client host/user/IP allowed to browse, site not banned, upload not too big)
	void requestChecks(HTTPHeader *header, NaughtyFilter *checkme, String *urld, String *url, std::string *clientip,
		std::string *clientuser, int filtergroup, bool &isbanneduser, bool &isbannedip, std::string &room);

	// strip the URL down to just the IP/hostname, then do an isIPHostname on the result
	bool isIPHostnameStrip(String url);

	// show the relevant banned page depending upon the report level settings, request type, etc.
	bool denyAccess(Socket *peerconn, Socket *proxysock, HTTPHeader *header, HTTPHeader *docheader,
		String *url, NaughtyFilter *checkme, std::string *clientuser, std::string *clientip,
		int filtergroup, bool ispostblock, int headersent, bool wasinfected, bool scanerror, bool forceshow = false);

	// create temporary ban bypass URLs/cookies
	String hashedURL(String *url, int filtergroup, std::string *clientip, bool infectionbypass);
	String hashedCookie(String *url, const char *magic, std::string *clientip, int bypasstimestamp);

	// do content scanning (AV filtering) and naughty filtering
	void contentFilter(HTTPHeader *docheader, HTTPHeader *header, DataBuffer *docbody, Socket *proxysock,
		Socket *peerconn, int *headersent, bool *pausedtoobig, off_t *docsize, NaughtyFilter *checkme,
		bool wasclean, int filtergroup, std::deque<CSPlugin *> &responsescanner, std::string *clientuser,
		std::string *clientip, bool *wasinfected, bool *wasscanned, bool isbypass, String &url, String &domain,
		bool *scanerror, bool &contentmodified, String *csmessage);

	// send a file to the client - used during bypass of blocked downloads
	off_t sendFile(Socket *peerconn, String & filename, String & filemime, String & filedis, String &url);
	
#ifdef __SSLCERT
	//ssl certificat checking
	void checkCertificate(String &hostname, Socket * sslSock, NaughtyFilter * checkme);
	
	int sendProxyConnect(String &hostname, Socket * sock, NaughtyFilter * checkme);
#endif //__SSLCERT

};

#endif
