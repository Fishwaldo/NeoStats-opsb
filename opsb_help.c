/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2005 Adam Rutter, Justin Hammond, Mark Hetherington
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

const char opsb_help_status_oneline[] = "View opsb state information";
const char opsb_help_lookup_oneline[] = "Lookup DNS record";
const char opsb_help_remove_oneline[] = "Remove an akill set by opsb";
const char opsb_help_check_oneline[] = "Scan a selected user";
const char opsb_help_ports_oneline[] = "Allows you to customize the ports scanned";
const char opsb_help_set_oneline[] = "Change opsb configuration options";

const char *opsb_help_lookup[] = {
	"Syntax: \2LOOKUP <ip|hostname> [type]\2",
	"",
	"Lookup DNS records for an ip address or hostname.",
	"The default lookup is the ip address for a hostname",
	"or the hostname for an ip address.",
	"",
	"Options for type are:",
	"    txt - text records",
	"    rp  - responsible person for this record",
	"    ns  - name servers for this record",
	"    soa - SOA for this record",
	"",
	NULL
};

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
	"Syntax: \2CHECK <nick|ip|hostname>\2",
	"",
	"This option will scan either a user connected to your",
	"network, an IP address, or Hostname for Insecure proxies,",
	"and report the status to you. If an Insecure proxy is",
	"found, the host will be banned from the network",
	NULL
};

const char *opsb_help_status[] = {
	"Syntax: \2STATUS\2",
	"",
	"Display status of the open proxy scanning bot",
	NULL
};

const char *opsb_help_set_doscan [] = {
	"\2SCAN <ON|OFF>\2",
	"Disables the proxy scan and only do a lookup in the DNS",
	"blacklist to see if this host is listed as an open proxy",
	NULL
};

const char *opsb_help_set_akill [] = {
	"\2AKILL <ON|OFF>\2",
	" ",
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

const char *opsb_help_set_opmdomain [] = {
	"\2OPMDOMAIN <domain>\2",
	"Domain used for blacklists.",
	"This setting should not be changed unless you know the",
	"effects in full",
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

const char *opsb_help_ports[] = {
	"Syntax: \2PORTS <LIST>\2",
	"        \2PORTS <ADD> <type> <port>\2",
	"        \2PORTS <DEL> <index>\2",
	"",
	"This command lets you view or manipulate the ports",
	"and proxy types scanned when users connect to your",
	"IRC network. By Default, OPSB scans some default Ports",
	"but you may wish to update this list with some additional",
	"protocols and ports custom to your network"
	"",
	"\2LIST\2 will list the current ports and protocols scanned",
	"and a ID number for use in removing entries.",
	"",
	"\2ADD\2 will add an entry of <type> running on port <port>",
	"to the port list.",
	"<type> can be either:", 
	"       HTTP",
	"       HTTPPOST",
	"       SOCKS4",
	"       SOCKS5",
	"       WINGATE",
	"       ROUTER",
	"and port can be any valid port number. The new port is scanned",
	"straight away",
	"",
	"\2DEL\2 will delete entry <index> from the list of",
	"ports. Requires a Restart of OPSB to become effective. Alternatively",
	"Reloading the OPSB module will make this effective",
	NULL
};

const char *opsb_help_remove[] = {
	"Syntax: \2REMOVE <ip|hostname>\2",
	"",
	"Remove akills that have been set by opsb.",
	"",
	"<ip|hostname> is the hostname listed in your akill list",
	"(usually found with /stats a)",
	NULL
};
