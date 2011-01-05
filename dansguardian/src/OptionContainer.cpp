//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@//jadeb/.com).
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


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "OptionContainer.hpp"
#include "RegExp.hpp"
#include "ConfigVar.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <syslog.h>

#include <unistd.h>		// checkme: remove?


// GLOBALS

extern bool is_daemonised;


// IMPLEMENTATION

OptionContainer::OptionContainer():numfg(0)
{
}

OptionContainer::~OptionContainer()
{
	reset();
}

void OptionContainer::reset()
{
	deleteFilterGroups();
	deletePlugins(dmplugins);
	deletePlugins(csplugins);
	deletePlugins(authplugins);
	exception_ip_list.reset();
	banned_ip_list.reset();
	html_template.reset();
	language_list.reset();
	conffile.clear();
	if (use_filter_groups_list) filter_groups_list.reset();
	filter_ip.clear();
}

void OptionContainer::deleteFilterGroups()
{
	for (int i = 0; i < numfg; i++) {
		if (fg[i] != NULL) {
#ifdef DGDEBUG
			std::cout << "In deleteFilterGroups loop" << std::endl;
#endif
			delete fg[i];  // delete extra FOptionContainer objects
			fg[i] = NULL;
		}
	}
	if (numfg > 0) {
		delete[]fg;
		numfg = 0;
	}
}

void OptionContainer::deletePlugins(std::deque<Plugin*> &list)
{
	for (std::deque<Plugin*>::iterator i = list.begin(); i != list.end(); i++) {
		if ((*i) != NULL) {
			(*i)->quit();
			delete (*i);
		}
	}
	list.clear();
}

bool OptionContainer::read(const char *filename, int type)
{
	conffilename = filename;
	// all sorts of exceptions could occur reading conf files
	try {
		std::string linebuffer;
		String temp;  // for tempory conversion and storage
		std::ifstream conffiles(filename, std::ios::in);  // dansguardian.conf
		if (!conffiles.good()) {
			if (!is_daemonised) {
				std::cerr << "error reading: " << filename << std::endl;
			}
			syslog(LOG_ERR, "%s", "error reading dansguardian.conf");
			return false;
		}
		while (!conffiles.eof()) {
			getline(conffiles, linebuffer);
			if (!conffiles.eof() && linebuffer.length() != 0) {
				if (linebuffer[0] != '#') {	// i.e. not commented out
					temp = (char *) linebuffer.c_str();
					if (temp.contains("#")) {
						temp = temp.before("#");
					}
					temp.removeWhiteSpace();  // get rid of spaces at end of line
					linebuffer = temp.toCharArray();
					conffile.push_back(linebuffer);  // stick option in deque
				}
			}
		}
		conffiles.close();

		if (type == 0 || type == 2) {

			if ((ipc_filename = findoptionS("ipcfilename")) == "")
				ipc_filename = "/tmp/.dguardianipc";

			if ((urlipc_filename = findoptionS("urlipcfilename")) == "")
				urlipc_filename = "/tmp/.dguardianurlipc";

			if ((ipipc_filename = findoptionS("ipipcfilename")) == "")
				ipipc_filename = "/tmp/.dguardianipipc";

			if ((pid_filename = findoptionS("pidfilename")) == "") {
				pid_filename = __PIDDIR;
				pid_filename += "/dansguardian.pid";
			}

			if (findoptionS("logsyslog") == "on") {
				log_syslog = true;
			} else 	if ((log_location = findoptionS("loglocation")) == "") {
				log_location = __LOGLOCATION;
				log_location += "/access.log";
				log_syslog = false;
			}

			if ((stat_location = findoptionS("statlocation")) == "") {
				stat_location = __LOGLOCATION;
				stat_location += "/stats";
			}

			if (type == 0) {
				return true;
			}
		}

		if ((daemon_user_name = findoptionS("daemonuser")) == "") {
			daemon_user_name = __PROXYUSER;
		}

		if ((daemon_group_name = findoptionS("daemongroup")) == "") {
			daemon_group_name = __PROXYGROUP;
		}

		blocked_content_store = findoptionS("blockedcontentstore");

		if (findoptionS("nodaemon") == "on") {
			no_daemon = true;
		} else {
			no_daemon = false;
		}

		if (findoptionS("nologger") == "on") {
			no_logger = true;
		} else {
			no_logger = false;
		}

		if (findoptionS("softrestart") == "on") {
			soft_restart = true;
		} else {
			soft_restart = false;
		}

#ifdef ENABLE_EMAIL
		// Email notification patch by J. Gauthier
		mailer = findoptionS("mailer");
#endif
	   
		// the dansguardian.conf and pics files get amalgamated into one
		// deque.  They are only seperate files for clarity.

		max_logitem_length = findoptionI("maxlogitemlength");
		if (!realitycheck(max_logitem_length, 0, 0, "maxlogitemlength")) {
			return false;
		}
		max_children = findoptionI("maxchildren");
		if (!realitycheck(max_children, 4, 0, "maxchildren")) {
			return false;
		}		// check its a reasonable value
		min_children = findoptionI("minchildren");
		if (!realitycheck(min_children, 1, max_children-1, "minchildren")) {
			return false;
		}		// check its a reasonable value
		maxspare_children = findoptionI("maxsparechildren");
		if (!realitycheck(maxspare_children, min_children, max_children, "maxsparechildren")) {
			return false;
		}		// check its a reasonable value
		prefork_children = findoptionI("preforkchildren");
		if (!realitycheck(prefork_children, 1, max_children, "preforkchildren")) {
			return false;
		}		// check its a reasonable value
		minspare_children = findoptionI("minsparechildren");
		if (!realitycheck(minspare_children, 0, maxspare_children-1, "minsparechildren")) {
			return false;
		}		// check its a reasonable value
		maxage_children = findoptionI("maxagechildren");
		if (!realitycheck(maxage_children, 1, 0, "maxagechildren")) {
			return false;
		}		// check its a reasonable value

		max_ips = findoptionI("maxips");
		if (!realitycheck(max_ips, 0, 0, "maxips")) {
			return false;
		}

		// TODO: Implement a "findoptionO" and a version of
		// reality check which uses off_t, for large file support?
		max_upload_size = findoptionI("maxuploadsize");
		if (!realitycheck(max_upload_size, -1, 0, "maxuploadsize")) {
			return false;
		}		// check its a reasonable value
		max_upload_size *= 1024;
		
		max_content_filter_size = findoptionI("maxcontentfiltersize");
		if (!realitycheck(max_content_filter_size, 0, 0, "maxcontentfiltersize")) {
			return false;
		}		// check its a reasonable value
		max_content_filter_size *= 1024;

		max_content_ramcache_scan_size = findoptionI("maxcontentramcachescansize");
		if (!realitycheck(max_content_ramcache_scan_size, 0, 0, "maxcontentramcachescansize")) {
			return false;
		}
		max_content_ramcache_scan_size *= 1024;

		max_content_filecache_scan_size = findoptionI("maxcontentfilecachescansize");
		if (!realitycheck(max_content_filecache_scan_size, 1, 0, "maxcontentfilecachescansize")) {
			return false;
		}
		max_content_filecache_scan_size *= 1024;
		
		if (max_content_ramcache_scan_size == 0) {
			max_content_ramcache_scan_size = max_content_filecache_scan_size;
		}
		if (max_content_filter_size == 0) {
			max_content_filter_size = max_content_ramcache_scan_size;
			if (max_content_filter_size == 0) {
				if (!is_daemonised)
					std::cerr << "maxcontent* settings cannot be zero (to disable phrase filtering, set weightedphrasemode to 0)" << std::endl;
				syslog(LOG_ERR, "%s", "maxcontent* settings cannot be zero (to disable phrase filtering, set weightedphrasemode to 0)");
				return false;
			}
		}
		if (max_content_filter_size > max_content_ramcache_scan_size) {
			if (!is_daemonised) {
				std::cerr << "maxcontentfiltersize can not be greater than maxcontentramcachescansize" << std::endl;
			}
			syslog(LOG_ERR, "%s", "maxcontentfiltersize can not be greater than maxcontentramcachescansize");
			return false;
		}
		if (max_content_ramcache_scan_size > max_content_filecache_scan_size) {
			if (!is_daemonised) {
				std::cerr << "maxcontentramcachescansize can not be greater than maxcontentfilecachescansize" << std::endl;
			}
			syslog(LOG_ERR, "%s", "maxcontentramcachescansize can not be greater than maxcontentfilecachescansize");
			return false;
		}

		bool contentscanning = findoptionM("contentscanner").size() > 0;
		if (contentscanning) {

			trickle_delay = findoptionI("trickledelay");
			if (!realitycheck(trickle_delay, 1, 0, "trickledelay")) {
				return false;
			}
			initial_trickle_delay = findoptionI("initialtrickledelay");
			if (!realitycheck(initial_trickle_delay, 1, 0, "initialtrickledelay")) {
				return false;
			}

			content_scanner_timeout = findoptionI("contentscannertimeout");
			if (!realitycheck(content_scanner_timeout, 1, 0, "contentscannertimeout")) {
				return false;
			}

			if (findoptionS("scancleancache") == "off") {
				scan_clean_cache = false;
			} else {
				scan_clean_cache = true;
			}

			if (findoptionS("contentscanexceptions") == "on") {
				content_scan_exceptions = true;
			} else {
				content_scan_exceptions = false;
			}

		}

		if (findoptionS("deletedownloadedtempfiles") == "off") {
			delete_downloaded_temp_files = false;
		} else {
			delete_downloaded_temp_files = true;
		}

		url_cache_number = findoptionI("urlcachenumber");
		if (!realitycheck(url_cache_number, 0, 0, "urlcachenumber")) {
			return false;
		}		// check its a reasonable value

		url_cache_age = findoptionI("urlcacheage");
		if (!realitycheck(url_cache_age, 0, 0, "urlcacheage")) {
			return false;
		}		// check its a reasonable value

		phrase_filter_mode = findoptionI("phrasefiltermode");
		if (!realitycheck(phrase_filter_mode, 0, 3, "phrasefiltermode")) {
			return false;
		}
		preserve_case = findoptionI("preservecase");
		if (!realitycheck(preserve_case, 0, 2, "preservecase")) {
			return false;
		}
		if (findoptionS("hexdecodecontent") == "on") {
			hex_decode_content = true;
		} else {
			hex_decode_content = false;
		}
		if (findoptionS("forcequicksearch") == "on") {
			force_quick_search = true;
		} else {
			force_quick_search = false;
		}
		
		if (findoptionS("usecustombannedimage") == "off") {
			use_custom_banned_image = false;
		} else {
			use_custom_banned_image = true;
		}
		custom_banned_image_file = findoptionS("custombannedimagefile");
		banned_image.read(custom_banned_image_file.c_str());

		if (findoptionS("usecustombannedflash") == "off") {
			use_custom_banned_flash = false;
		} else {
			use_custom_banned_flash = true;
		}
		custom_banned_flash_file = findoptionS("custombannedflashfile");
		banned_flash.read(custom_banned_flash_file.c_str());
		
		filter_port = findoptionI("filterport");
		if (!realitycheck(filter_port, 1, 65535, "filterport")) {
			return false;
		}		// check its a reasonable value
		proxy_port = findoptionI("proxyport");
		if (!realitycheck(proxy_port, 1, 65535, "proxyport")) {
			return false;
		}		// etc
		proxy_ip = findoptionS("proxyip");

		// multiple listen IP support
		filter_ip = findoptionM("filterip");
		if (filter_ip.size() > 127) {
			if (!is_daemonised) {
				std::cerr << "Can not listen on more than 127 IPs" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Can not listen on more than 127 IPs");
			return false;
		}

#ifdef ENABLE_ORIG_IP
		if (findoptionS("originalip") == "off") {
			get_orig_ip = false;
		} else {
			get_orig_ip = true;
		}
#endif

		ll = findoptionI("loglevel");
		if (!realitycheck(ll, 0, 3, "loglevel")) {
			return false;
		}		// etc
		log_file_format = findoptionI("logfileformat");
		if (!realitycheck(log_file_format, 1, 4, "logfileformat")) {
			return false;
		}		// etc
		if (findoptionS("anonymizelogs") == "on") {
			anonymise_logs = true;
		} else {
			anonymise_logs = false;
		}
		if (findoptionS("logadblocks") == "on") {
			log_ad_blocks = true;
		} else {
			log_ad_blocks = false;
		}
		if (findoptionS("logtimestamp") == "on") {
			log_timestamp = true;
		} else {
			log_timestamp = false;
		}
		if (findoptionS("loguseragent") == "on") {
			log_user_agent = true;
		} else {
			log_user_agent = false;
		}

		logid_1.assign(findoptionS("logid1"));
		if (logid_1.empty())
			logid_1.assign("-");
		logid_2.assign(findoptionS("logid2"));
		if (logid_2.empty())
			logid_2.assign("-");

#ifdef SG_LOGFORMAT
		prod_id.assign(findoptionS("productid"));
		if (prod_id.empty())
			// SG '08
			prod_id.assign("2");
#endif

		if (findoptionS("showweightedfound") == "on") {
			show_weighted_found = true;
		} else {
			show_weighted_found = false;
		}
		weighted_phrase_mode = findoptionI("weightedphrasemode");
		if (!realitycheck(weighted_phrase_mode, 0, 2, "weightedphrasemode")) {
			return false;
		}
		reporting_level = findoptionI("reportinglevel");
		if (!realitycheck(reporting_level, -1, 3, "reportinglevel")) {
			return false;
		}
		languagepath = findoptionS("languagedir") + "/" + findoptionS("language") + "/";
		html_template_location = languagepath + "template.html";

		if (findoptionS("forwardedfor") == "on") {
			forwarded_for = true;
		} else {
			forwarded_for = false;
		}
		log_exception_hits = findoptionI("logexceptionhits");
		if (!realitycheck(log_exception_hits, 0, 2, "logexceptionhits")) {
			return false;
		}
		if (findoptionS("nonstandarddelimiter") == "off") {
			non_standard_delimiter = false;
		} else {
			non_standard_delimiter = true;
		}
		if (findoptionS("createlistcachefiles") == "off") {
			createlistcachefiles = false;
		} else {
			createlistcachefiles = true;
		}
		if (findoptionS("logconnectionhandlingerrors") == "on") {
			logconerror = true;
		} else {
			logconerror = false;
		}
		if (findoptionS("logchildprocesshandling") == "on") {
			logchildprocs = true;
		} else {
			logchildprocs = false;
		}

		if (findoptionS("reverseaddresslookups") == "on") {
			reverse_lookups = true;
		} else {
			reverse_lookups = false;
		}
		if (findoptionS("reverseclientiplookups") == "on") {
			reverse_client_ip_lookups = true;
		} else {
			reverse_client_ip_lookups = false;
		}
		if (findoptionS("logclienthostnames") == "on") {
			log_client_hostnames = true;
		} else {
			log_client_hostnames = false;
		}

		if (findoptionS("recheckreplacedurls") == "on") {
			recheck_replaced_urls = true;
		} else {
			recheck_replaced_urls = false;
		}

		if (findoptionS("usexforwardedfor") == "on") {
			use_xforwardedfor = true;
		} else {
			use_xforwardedfor = false;
		}

		filter_groups = findoptionI("filtergroups");

		if (!realitycheck(filter_groups, 1, 0, "filtergroups")) {
			return false;
		}
		if (filter_groups < 1) {
			if (!is_daemonised) {
				std::cerr << "filtergroups too small" << std::endl;
			}
			syslog(LOG_ERR, "filtergroups too small");
			return false;
		}

		if (!loadDMPlugins()) {
			if (!is_daemonised) {
				std::cerr << "Error loading DM plugins" << std::endl;
			}
			syslog(LOG_ERR, "Error loading DM plugins");
			return false;
		}

		// this needs to be known before loading CS plugins,
		// because ClamAV plugin makes use of it during init()
		download_dir = findoptionS("filecachedir");

		if (contentscanning) {
			if (!loadCSPlugins()) {
				if (!is_daemonised) {
					std::cerr << "Error loading CS plugins" << std::endl;
				}
				syslog(LOG_ERR, "Error loading CS plugins");
				return false;
			}
		}
		
		if (!loadAuthPlugins()) {
			if (!is_daemonised) {
				std::cerr << "Error loading auth plugins" << std::endl;
			}
			syslog(LOG_ERR, "Error loading auth plugins");
			return false;
		}

		// if there's no auth enabled, we only need the first group's settings
		if (authplugins.size() == 0)
			filter_groups = 1;

		filter_groups_list_location = findoptionS("filtergroupslist");
		std::string banned_ip_list_location(findoptionS("bannediplist"));
		std::string exception_ip_list_location(findoptionS("exceptioniplist"));
		group_names_list_location = findoptionS("groupnamesfile");
		std::string language_list_location(languagepath + "messages");
		if (reporting_level == 1 || reporting_level == 2) {
			access_denied_address = findoptionS("accessdeniedaddress");
			access_denied_domain = access_denied_address.c_str();
			access_denied_domain = access_denied_domain.after("://");
			access_denied_domain.removeWhiteSpace();
			if (access_denied_domain.contains("/")) {
				access_denied_domain = access_denied_domain.before("/");  // access_denied_domain now contains the FQ host nom of the
				// server that serves the accessdenied.html file
			}
			if (access_denied_domain.contains(":")) {
				access_denied_domain = access_denied_domain.before(":");  // chop off the port number if any
			}
			if (access_denied_domain.length() < 4) {
				if (!is_daemonised) {
					std::cerr << "accessdeniedaddress setting appears to be wrong." << std::endl;
				}
				syslog(LOG_ERR, "%s", "accessdeniedaddress setting appears to be wrong.");
				return false;
			}
		}

		if (filter_groups_list_location.length() == 0) {
			use_filter_groups_list = false;
#ifdef DGDEBUG
			std::cout << "Not using filtergroupslist" << std::endl;
#endif
		} else if (!doReadItemList(filter_groups_list_location.c_str(),&filter_groups_list,"filtergroupslist",true)) {
			return false;
		} else {
			use_filter_groups_list = true;
		}

		if (group_names_list_location.length() == 0) {
			use_group_names_list = false;
#ifdef DGDEBUG
			std::cout << "Not using groupnameslist" << std::endl;
#endif
		} else {
			use_group_names_list = true;
		}

		if (findoptionS("prefercachedlists") == "on")
			prefer_cached_lists = true;
		else
			prefer_cached_lists = false;

		if (!exception_ip_list.readIPMelangeList(exception_ip_list_location.c_str()))
		{
			std::cout << "Failed to read exceptioniplist" << std::endl;
			return false;
		}
		if (!banned_ip_list.readIPMelangeList(banned_ip_list_location.c_str()))
		{
			std::cout << "Failed to read bannediplist" << std::endl;
			return false;
		}

		if (!language_list.readLanguageList(language_list_location.c_str())) {
			return false;
		}		// messages language file

		if (reporting_level == 3) {	// only if reporting set to HTML templ
			if (!html_template.readTemplateFile(html_template_location.c_str())) {
				if (!is_daemonised) {
					std::cerr << "Error reading HTML Template file: " << html_template_location << std::endl;
				}
				syslog(LOG_ERR, "Error reading HTML Template file: %s", html_template_location.c_str());
				return false;
				// HTML template file
			}
		}

		if (!readFilterGroupConf()) {
			if (!is_daemonised) {
				std::cerr << "Error reading filter group conf file(s)." << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error reading filter group conf file(s).");
			return false;
		}

	}
	catch(std::exception & e) {
		if (!is_daemonised) {
			std::cerr << e.what() << std::endl;  // when called the daemon has not
			// detached so we can do this
		}
		return false;
	}
	return true;
}

bool OptionContainer::doReadItemList(const char* filename, ListContainer* lc, const char* fname, bool swsort) {
	bool result = lc->readItemList(filename, false, 0);
	if (!result) {
		if (!is_daemonised) {
			std::cerr << "Error opening " << fname << std::endl;
		}
		syslog(LOG_ERR, "Error opening %s", fname);
		return false;
	}
	if (swsort)
		lc->doSort(true);
	else
		lc->doSort(false);
	return true;
}

bool OptionContainer::inExceptionIPList(const std::string *ip, std::string *&host)
{
	return exception_ip_list.inList(*ip, host);
}

bool OptionContainer::inBannedIPList(const std::string *ip, std::string *&host)
{
	return banned_ip_list.inList(*ip, host);
}


long int OptionContainer::findoptionI(const char *option)
{
	long int res = String(findoptionS(option).c_str()).toLong();
	return res;
}


std::string OptionContainer::findoptionS(const char *option)
{
	// findoptionS returns a found option stored in the deque
	String temp;
	String temp2;
	String o(option);
	for (int i = 0; i < (signed) conffile.size(); i++) {
		temp = conffile[i].c_str();
		temp2 = temp.before("=");
		while (temp2.endsWith(" ")) {	// get rid of tailing spaces before =
			temp2.chop();
		}
		if (o == temp2) {
			temp = temp.after("=");
			while (temp.startsWith(" ")) {	// get rid of heading spaces
				temp.lop();
			}
			if (temp.startsWith("'")) {	// inverted commas
				temp.lop();
			}
			while (temp.endsWith(" ")) {	// get rid of tailing spaces
				temp.chop();
			}
			if (temp.endsWith("'")) {	// inverted commas
				temp.chop();
			}
			return temp.toCharArray();
		}
	}
	return "";
}


std::deque<String > OptionContainer::findoptionM(const char *option)
{
	// findoptionS returns all the matching options
	String temp;
	String temp2;
	String o(option);
	std::deque<String > results;
	for (int i = 0; i < (signed) conffile.size(); i++) {
		temp = conffile[i].c_str();
		temp2 = temp.before("=");
		while (temp2.endsWith(" ")) {	// get rid of tailing spaces before =
			temp2.chop();
		}
		if (o == temp2) {
			temp = temp.after("=");
			while (temp.startsWith(" ")) {	// get rid of heading spaces
				temp.lop();
			}
			if (temp.startsWith("'")) {	// inverted commas
				temp.lop();
			}
			while (temp.endsWith(" ")) {	// get rid of tailing spaces
				temp.chop();
			}
			if (temp.endsWith("'")) {	// inverted commas
				temp.chop();
			}
			results.push_back(temp);
		}
	}
	return results;
}

bool OptionContainer::realitycheck(long int l, long int minl, long int maxl, const char *emessage)
{
	// realitycheck checks an amount for certain expected criteria
	// so we can spot problems in the conf files easier
	if ((l < minl) || ((maxl > 0) && (l > maxl))) {
		if (!is_daemonised) {
			// when called we have not detached from
			// the console so we can write back an
			// error

			std::cerr << "Config problem; check allowed values for " << emessage << std::endl;
		}
		syslog(LOG_ERR, "Config problem; check allowed values for %s", emessage);
		return false;
	}
	return true;
}


bool OptionContainer::readFilterGroupConf()
{
	String prefix(conffilename);
	prefix = prefix.before(".conf");
	prefix += "f";
	String file;
	ConfigVar groupnamesfile;
	String groupname;
	bool need_html = false;
	if (use_group_names_list) {
		int result = groupnamesfile.readVar(group_names_list_location.c_str(), "=");
		if (result != 0) {
			if (!is_daemonised)
				std::cerr << "Error opening group names file: " << group_names_list_location << std::endl;
			syslog(LOG_ERR, "Error opening group names file: %s", group_names_list_location.c_str());
			return false;
		}
	}
	for (int i = 1; i <= filter_groups; i++) {
		file = prefix + String(i);
		file += ".conf";
		if (use_group_names_list) {
			std::ostringstream groupnum;
			groupnum << i;
			groupname = groupnamesfile[groupnum.str().c_str()];
			if (groupname.length() == 0) {
				if (!is_daemonised)
					std::cerr << "Group names file too short: " << group_names_list_location << std::endl;
				syslog(LOG_ERR, "Group names file too short: %s", group_names_list_location.c_str());
				return false;
			}
#ifdef DGDEBUG
			std::cout << "Group name: " << groupname << std::endl;
#endif
		}
		if (!readAnotherFilterGroupConf(file.toCharArray(), groupname.toCharArray(), need_html)) {
			if (!is_daemonised) {
				std::cerr << "Error opening filter group config: " << file << std::endl;
			}
			syslog(LOG_ERR, "Error opening filter group config: %s", file.toCharArray());
			return false;
		}
	}
	if (!need_html && (reporting_level != 3)) {
#ifdef DGDEBUG
		std::cout << "Global reporting level not 3 & no filter groups using the template; so resetting it." << std::endl;
#endif
		html_template.reset();
	}
	return true;
}

bool OptionContainer::readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html)
{
#ifdef DGDEBUG
	std::cout << "adding filter group: " << numfg << " " << filename << std::endl;
#endif

	// array of pointers to FOptionContainer
	typedef FOptionContainer *PFOptionContainer;
	FOptionContainer **temp = new PFOptionContainer[numfg + 1];
	for (int i = 0; i < numfg; i++) {
		temp[i] = fg[i];
	}
	if (numfg > 0) {
		delete[]fg;
	}
	fg = temp;
	fg[numfg] = new FOptionContainer;

#ifdef DGDEBUG
	std::cout << "added filter group: " << numfg << " " << filename << std::endl;
#endif

	// pass all the vars from OptionContainer needed
	(*fg[numfg]).weighted_phrase_mode = weighted_phrase_mode;
	(*fg[numfg]).force_quick_search = force_quick_search;
	(*fg[numfg]).createlistcachefiles = createlistcachefiles;
	(*fg[numfg]).reverse_lookups = reverse_lookups;
	
	// pass in default access denied address - can be overidden
	(*fg[numfg]).access_denied_domain = access_denied_domain;
	(*fg[numfg]).access_denied_address = access_denied_address;
	
	// pass in the group name
	(*fg[numfg]).name = groupname;

	// pass in the reporting level - can be overridden
	(*fg[numfg]).reporting_level = reporting_level;

#ifdef DGDEBUG
	std::cout << "passed variables to filter group: " << numfg << " " << filename << std::endl;
#endif

	bool rc = (*fg[numfg]).read(filename);
#ifdef DGDEBUG
	std::cout << "read filter group: " << numfg << " " << filename << std::endl;
#endif

	numfg++;

	if (!rc) {
		return false;
	}

	if ((fg[numfg-1]->reporting_level == 3) && (html_template.html.size() == 0)) {
#ifdef DGDEBUG
		std::cout << "One of the groups has overridden the reporting level! Loading the HTML template." << std::endl;
#endif
		need_html = true;
		if (!html_template.readTemplateFile(html_template_location.c_str())) {
			if (!is_daemonised) {
				std::cerr << "Error reading HTML Template file: " << html_template_location << std::endl;
			}
			syslog(LOG_ERR, "Error reading HTML Template file: %s", html_template_location.c_str());
			return false;
			// HTML template file
		}
	}

	return true;
}

bool OptionContainer::loadDMPlugins()
{
	std::deque<String > dq = findoptionM("downloadmanager");
	unsigned int numplugins = dq.size();
	if (numplugins < 1) {
		if (!is_daemonised) {
			std::cerr << "There must be at least one download manager option" << std::endl;
		}
		syslog(LOG_ERR, "%s", "There must be at least one download manager option");
		return false;
	}
	String config;
	for (unsigned int i = 0; i < numplugins; i++) {
		config = dq[i];
#ifdef DGDEBUG
		std::cout << "loading download manager config: " << config << std::endl;
#endif
		DMPlugin *dmpp = dm_plugin_load(config.toCharArray());
		if (dmpp == NULL) {
			if (!is_daemonised) {
				std::cerr << "dm_plugin_load() returned NULL pointer with config file: " << config << std::endl;
			}
			syslog(LOG_ERR, "dm_plugin_load() returned NULL pointer with config file: %s", config.toCharArray());
			return false;
		}
		bool lastplugin = (i == (numplugins - 1));
		int rc = dmpp->init(&lastplugin);
		if (rc < 0) {
			if (!is_daemonised) {
				std::cerr << "Download manager plugin init returned error value: " << rc << std::endl;
			}
			syslog(LOG_ERR, "Download manager plugin init returned error value: %d", rc);
			return false;
		}
		else if (rc > 0) {
			if (!is_daemonised) {
				std::cerr << "Download manager plugin init returned warning value: " << rc << std::endl;
			}
			syslog(LOG_ERR, "Download manager plugin init returned warning value: %d", rc);
		}
		dmplugins.push_back(dmpp);
	}
	// cache reusable iterators
	dmplugins_begin = dmplugins.begin();
	dmplugins_end = dmplugins.end();
	return true;
}

bool OptionContainer::loadCSPlugins()
{
	std::deque<String > dq = findoptionM("contentscanner");
	unsigned int numplugins = dq.size();
	if (numplugins < 1) {
		return true;  // to have one is optional
	}
	String config;
	for (unsigned int i = 0; i < numplugins; i++) {
		config = dq[i];
		// worth adding some input checking on config
#ifdef DGDEBUG
		std::cout << "loading content scanner config: " << config << std::endl;
#endif
		CSPlugin *cspp = cs_plugin_load(config.toCharArray());
		if (cspp == NULL) {
			if (!is_daemonised) {
				std::cerr << "cs_plugin_load() returned NULL pointer with config file: " << config << std::endl;
			}
			syslog(LOG_ERR, "cs_plugin_load() returned NULL pointer with config file: %s", config.toCharArray());
			return false;
		}
#ifdef DGDEBUG
		std::cout << "Content scanner plugin is good, calling init..." << std::endl;
#endif
		int rc = cspp->init(NULL);
		if (rc < 0) {
			if (!is_daemonised) {
				std::cerr << "Content scanner plugin init returned error value: " << rc << std::endl;
			}
			syslog(LOG_ERR, "Content scanner plugin init returned error value: %d", rc);
			return false;
		}
		else if (rc > 0) {
			if (!is_daemonised) {
				std::cerr << "Content scanner plugin init returned warning value: " << rc << std::endl;
			}
			syslog(LOG_ERR, "Content scanner plugin init returned warning value: %d", rc);
		}
		csplugins.push_back(cspp);
	}
	// cache reusable iterators
	csplugins_begin = csplugins.begin();
	csplugins_end = csplugins.end();
	return true;
}

bool OptionContainer::loadAuthPlugins()
{
	// Assume no auth plugins need an upstream proxy query (NTLM, BASIC) until told otherwise
	auth_needs_proxy_query = false;

	std::deque<String > dq = findoptionM("authplugin");
	unsigned int numplugins = dq.size();
	if (numplugins < 1) {
		return true;  // to have one is optional
	}
	String config;
	for (unsigned int i = 0; i < numplugins; i++) {
		config = dq[i];
		// worth adding some input checking on config
#ifdef DGDEBUG
		std::cout << "loading auth plugin config: " << config << std::endl;
#endif
		AuthPlugin *app = auth_plugin_load(config.toCharArray());
		if (app == NULL) {
			if (!is_daemonised) {
				std::cerr << "auth_plugin_load() returned NULL pointer with config file: " << config << std::endl;
			}
			syslog(LOG_ERR, "auth_plugin_load() returned NULL pointer with config file: %s", config.toCharArray());
			return false;
		}
#ifdef DGDEBUG
		std::cout << "Auth plugin is good, calling init..." << std::endl;
#endif
		int rc = app->init(NULL);
		if (rc < 0) {
			if (!is_daemonised) {
				std::cerr << "Auth plugin init returned error value: " << rc << std::endl;
			}
			syslog(LOG_ERR, "Auth plugin init returned error value: %d", rc);
			return false;
		}
		else if (rc > 0) {
			if (!is_daemonised) {
				std::cerr << "Auth plugin init returned warning value: " << rc << std::endl;
			}
			syslog(LOG_ERR, "Auth plugin init returned warning value: %d", rc);
		}

		if (app->needs_proxy_query) {
			auth_needs_proxy_query = true;
#ifdef DGDEBUG
			std::cout << "Auth plugin relies on querying parent proxy" << std::endl;
#endif
		}
		authplugins.push_back(app);
	}
	// cache reusable iterators
	authplugins_begin = authplugins.begin();
	authplugins_end = authplugins.end();
	return true;
}
