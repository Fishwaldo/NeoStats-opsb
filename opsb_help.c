/* NeoStats - IRC Statistical Services Copyright (c) 1999-2002 NeoStats Group Inc.
** Copyright (c) 1999-2002 Adam Rutter, Justin Hammond
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

#include "stats.h"

const char *opsb_help[] = {
	"\2Open Proxy Scanning Bot\2 scans the network for insecure",
	"clients. For more info \2/msg opsb info\2",
	"",
	"The following commands can be used with opsb",
	"",
	"    LOOKUP     Lookup DNS record",
	"    INFO       Information about opsb",
	NULL
};

const char *opsb_help_oper[] = {
	"",
	"Additional commands for Operators",
	"",
	"    CHECK      Scan a selected user",
	"    STATUS     View opsb state information",
	"    SET        Change opsb configuration options",
	"    EXCLUDE    Exclude a host from scanning",
	"    REMOVE     Remove an akill set by opsb",
	NULL
};

const char *opsb_help_on_help[] = {
	"",
	"To use a command, type",
	"    \2/msg opsb command\2",
	"For for more information on a command, type", 
	"    \2/msg opsb HELP command\2.",
	NULL
};


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

const char *opsb_help_info[] = {
	"\2Open Proxy Scanning Bot Information\2",
	"",
	"This bot is intended to scan clients connecting to this",
	"network for insecure proxies. Insecure proxies are often",
	"used to attack networks or channel with \2clone\2 bots",
	"This check scans the following ports:", 
	"    3128, 8080, 80 23 and 1080",
	"If you have Firewall, or IDS software, please ignore any",
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

const char *opsb_help_set[] = {
	"Syntax: \2SET <OPTION> <SETTING>\2",
	"",
	"This command will set various options relating to OPSB.",
	"You can view the settings by typing \2SET LIST\2",
	"The Settings take effect straight away",
	"The Options are:",
	"    \2TARGETIP\2      - Change the IP address we try to",
	"                        make the proxies connect to",
	"                        This should be set to an IP address",
	"                        of one of your IRC Servers.",
	"    \2TARGETPORT\2    - Change the Port number we try to",
	"                        make proxies connect to. This must",
	"                        be a port that runs on your IRCD",
	"    \2CACHETIME\2     - Amount of time (in seconds) that",
	"                        an entry will be cached",
	"    \2DISABLESCAN\2   - Disables the proxy scan and only",
	"                        do a lookup in the DNS blacklist",
	"                        to see if this host is listed as",
	"                        an open proxy",
	"\2Advanced Settings\2 - These settings should not be changed",
	"                        unless you know the effects in full",
	"    \2OPMDOMAIN\2     - Change the Domain we use to lookup",
	"                        for Blacklists.",
	"    \2MAXBYTES\2      - Maximum number of bytes we receive",
	"                        from a proxy before disconnecting",
	"    \2TIMEOUT\2       - Time we wait for a proxy to respond",
	"                        to our servers before disconnecting,",
	"                        and assuming its not an open Proxy",
	"    \2OPENSTRING\2    - The string we expect to see if",
	"                        there is an Open Proxy",
	"    \2SPLITTIME\2     - This is used to determine if users",
	"                        connecting to the network are part",
	"                        of a Net join",
	"                        (when two servers link together)",
	"    \2SCANMSG\2       - This is the message sent to a user",
	"                        when we scan their hosts",
	"    \2BANTIME\2       - This is how long the user will be",
	"                        banned from the network for",
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

const char *opsb_help_remove[] = {
	"Syntax: \2REMOVE <ip|hostname>\2",
	"",
	"Remove akills that have been set by opsb.",
	"",
	"<ip|hostname> is the hostname listed in your akill list",
	"(usually found with /stats a)",
	NULL
};
