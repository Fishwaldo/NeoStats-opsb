/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2006 Adam Rutter, Justin Hammond, Mark Hetherington
** http://www.neostats.net/
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
**  USA
**
** NeoStats CVS Identification
** $Id$
*/

#include "neostats.h"

const char *opsb_about[] = {
	"\2Open Proxy Scanning Bot Information\2",
	"",
	"This service scans clients connecting to this network for",
	"insecure proxies. Insecure proxies are often used to attack",
	"networks or channels with clone bots. If you have a firewall,",
	"or IDS software, please ignore any errors that this scan",
	"may generate.",
	"",
	"If you have any further questions, please contact network",
	"administration.",
	NULL
};

const char *opsb_help_check[] = {
	"Scan a user, ip address or host",
	"Syntax: \2CHECK <nick|ip|hostname>\2",
	"",
	"This option will scan either a user connected to your",
	"network, an IP address, or Hostname for Insecure proxies,",
	"and report the status to you. If an Insecure proxy is",
	"found, the host will be banned from the network",
	NULL
};

const char *opsb_help_status[] = {
	"Display opsb status",
	"Syntax: \2STATUS\2",
	"",
	"Display status of the open proxy scanning bot",
	NULL
};

const char *opsb_help_add[] = {
	"Add a port to scanning",
	"Syntax: \2ADD <type> <port>\2",
	"",
	"Add an entry to the port scan list.",
	"<type> must be one of:", 
	"    HTTP, HTTPPOST, SOCKS4, SOCKS5, WINGATE, ROUTER",
	"<port> must be a valid port number.",
	"The new port is scanned straight away",
	NULL
};

const char *opsb_help_del[] = {
	"Delete a port from scanning",
	"Syntax: \2DEL <index>\2",
	"",
	"Delete entry <index> from the list of ports. ",
	"Requires a restart of OPSB to become effective.",
	NULL
};

const char *opsb_help_list[] = {
	"List protocols and ports scanned",
	"Syntax: \2LIST\2",
	"",
	"List the current ports and protocols scanned",
	"and a ID number for use in removing entries.",
	NULL
};

const char *opsb_help_remove[] = {
	"Remove an akill set by opsb",
	"Syntax: \2REMOVE <ip|hostname>\2",
	"",
	"Remove akills that have been set by opsb.",
	"<ip|hostname> is the hostname listed in your akill list",
	"(usually found with /stats a)",
	NULL
};

const char *opsb_help_set_akill [] = {
	"\2AKILL <ON|OFF>\2",
	"Whether to issue an akill for positive lookups",
	NULL
};

const char *opsb_help_set_targetip [] = {
	"\2TARGETIP <ip>\2",
	"IP address of server we try to make the proxies connect to",
	NULL
};

const char *opsb_help_set_targetport [] = {
	"\2TARGETPORT <port>\2",
	"IRCd port number we try to make proxies connect to.",
	NULL
};

const char *opsb_help_set_maxbytes [] = {
	"\2MAXBYTES <max>\2",
	"Maximum number of bytes we receive from a proxy before disconnecting",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_timeout [] = {
	"\2TIMEOUT <time>\2",
	"Time we wait for a proxy to respond to our servers before",
	"disconnecting and assuming its not an open proxy.",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_openstring [] = {
	"\2OPENSTRING <string>\2",
	"The string we expect to see if there is an open proxy",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_scanmsg [] = {
	"\2SCANMSG <msg>\2",
	"Message sent to a user when we scan their hosts",
	NULL
};

const char *opsb_help_set_akilltime [] = {
	"\2AKILLTIME <time>\2",
	"How long the user will be banned from the network for",
	NULL
};

const char *opsb_help_set_cachetime [] = {
	"\2CACHETIME <time>\2",
	"Time (in seconds) that an entry will be cached",
	NULL
};

const char *opsb_help_set_cachesize [] = {
	"\2CACHESIZE <size>\2",
	"The total number of clean hosts that OPSB will cache",
	"Setting this too large may cause NeoStats to Lag",
	NULL
};

const char *opsb_help_set_verbose [] = {
	"\2VERBOSE <ON|OFF>\2",
	"Whether OPSB is verbose in operation or not",
	NULL
};

const char *opsb_help_set_exclusions[] = {
	"\2EXCLUSIONS <ON|OFF>\2",
	"Use global exclusion list in addition to local exclusion list",
	NULL
};
const char *opsb_help_set_doreport[] = {
	"Enable Open Proxy Reporting",
	"\2DOREPORT <ON|OFF>\2",
	"Enable OPSB reporting of Open Proxies back to Secure.irc-chat.net",
	NULL
};
