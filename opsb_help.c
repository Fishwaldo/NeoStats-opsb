/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2004 Adam Rutter, Justin Hammond, Mark Hetherington
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
const char opsb_help_exclude_oneline[] = "Exclude a host from scanning";
const char opsb_help_ports_oneline[] = "Allows you to customize the ports scanned";
const char opsb_help_set_oneline[] = "Change opsb configuration options";

const char *opsb_help_lookup[] = {
	"Syntax: \2LOOKUP <ip|hostname> <flag>\2",
	"",
	"This command allows you to lookup DNS records on the",
	"Internet. Different types of records can be looked up",
	"by specifying different flags",
	"",
	"The Flags are:",
	"    txt - Lookup Text Records",
	"    rp  - Lookup the Responsible Person for this record",
	"    ns  - Lookup the Name Servers for this record",
	"    soa - Lookup the SOA for this Record",
	"",
	"If you do not specify a flag, it defaults to looking up",
	"either the IP address for Hostnames, or the Hostname for",
	"IP addresses",
	NULL
};

const char *opsb_about[] = {
	"\2Open Proxy Scanning Bot Information\2",
	"",
	"This bot is intended to scan clients connecting to this",
	"network for insecure proxies. Insecure proxies are often",
	"used to attack networks or channels with clone bots",
	"If you have a firewall, or IDS software, please ignore any",
	"errors that this scan may generate",
	"",
	"If you have any further questions, please contact network",
	"administration staff",
	NULL
};

const char *opsb_help_check[] = {
	"Syntax: \2CHECK <nickname/IP/hostname>\2",
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
	"View detailed information about the state of the Open",
	"Proxy Scanning Bot",
	NULL
};

const char *opsb_help_set_disablescan [] = {
	"\2DISABLESCAN\2",
	"Disables the proxy scan and only do a lookup in the DNS",
	"blacklist to see if this host is listed as an open proxy",
	NULL
};

const char *opsb_help_set_doban [] = {
	"\2DOBAN\2",
	" ",
	NULL
};

const char *opsb_help_set_targetip [] = {
	"\2TARGETIP\2",
	"Change the IP address we try to make the proxies connect to",
	"This should be set to an IP address of one of your IRC Servers.",
	NULL
};

const char *opsb_help_set_targetport [] = {
	"\2TARGETPORT\2",
	"Change the Port number we try to make proxies connect to.",
	"This must be a port that runs on your IRCD",
	NULL
};

const char *opsb_help_set_opmdomain [] = {
	"\2OPMDOMAIN\2",
	"Change the Domain we use to lookup for Blacklists.",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_maxbytes [] = {
	"\2MAXBYTES\2",
	"Maximum number of bytes we receive from a proxy before disconnecting",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_timeout [] = {
	"\2TIMEOUT\2",
	"Time we wait for a proxy to respond to our servers before",
	"disconnecting and assuming its not an open proxy.",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_openstring [] = {
	"\2OPENSTRING\2",
	"The string we expect to see if there is an open proxy",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_scanmsg [] = {
	"\2SCANMSG\2",
	"Message sent to a user when we scan their hosts",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_bantime [] = {
	"\2BANTIME\2",
	"How long the user will be banned from the network for",
	"This setting should not be changed unless you know the",
	"effects in full",
	NULL
};

const char *opsb_help_set_cachetime [] = {
	"\2CACHETIME\2",
	"Time (in seconds) that an entry will be cached",
	NULL
};

const char *opsb_help_set_verbose [] = {
	"\2VERBOSE\2",
	"Whether OPSB is verbose in operation or not",
	NULL
};

const char *opsb_help_exclude[] = {
	"Syntax: \2EXCLUDE <LIST>\2",
	"        \2EXCLUDE <ADD> <hostname> <type> <reason>\2",
	"        \2EXCLUDE <DEL> <index>\2",
	"",
	"This command lets you view or manipulate the exception",
	"list. Exception lists are used to exclude users, or",
	"servers from scanning. You should at least add a server",
	"entry for your services IRC name, to stop OPSB from",
	"scanning Nickserv, Chanserv etc",
	"",
	"\2LIST\2 will list the current exceptions together with an",
	"ID number for use in removing entries.",
	"",
	"\2ADD\2 will add an entry of <hostname> to the exception" 
	"list. Flag should be 1 to indicate a server name",
	"(eg, services.irc-chat.net) or 0 to indicate a hostname",
	"(eg, *.adsl.home.com). Reason allows you to set a"
	"reason for the exclusion for future reference",
	"Wildcards such as * and ? may be used in the hostname.",
	"",
	"\2DEL\2 will delete entry <index> from the list of",
	"exclusions. Use the LIST command to find the index.",
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
