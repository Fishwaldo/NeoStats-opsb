/* NeoStats - IRC Statistical Services Copyright (c) 1999-2004 NeoStats Group Inc.
** Copyright (c) 1999-2004 Adam Rutter, Justin Hammond
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


#include <stdio.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include "dl.h"
#include "stats.h"
#include "conf.h"
#include "opsb.h"
#include "log.h"

void reportdns(char *data, adns_answer *a);
void dnsblscan(char *data, adns_answer *a);
static int ScanNick(char **av, int ac);
int startscan(scaninfo *scandata);
int do_set(User *u, char **av, int ac);
void save_ports();
void unconf();
void save_exempts(exemptinfo *exempts);


extern const char *opsb_help[];
extern const char *opsb_help_on_help[];
extern const char *opsb_help_oper[];
extern const char *opsb_help_lookup[];
extern const char *opsb_help_info[];
extern const char *opsb_help_check[];
extern const char *opsb_help_status[];
extern const char *opsb_help_set[];
extern const char *opsb_help_exclude[];
extern const char *opsb_help_remove[];
extern const char *opsb_help_ports[];

char s_opsb[MAXNICK];

int online;

ModuleInfo __module_info = {
	"OPSB",
	"An Open Proxy Scanning Bot",
	"2.1",
	__DATE__,
	__TIME__
};

int new_m_version(char *origin, char **av, int ac) {
	snumeric_cmd(RPL_VERSION,origin, "Module OPSB Loaded, Version: %s %s %s",__module_info.module_version,__module_info.module_build_date,__module_info.module_build_time);
	return 0;
}

Functions __module_functions[] = {
	{ MSG_VERSION,	new_m_version,	1 },
#ifdef HAVE_TOKEN_SUP
	{ TOK_VERSION,	new_m_version,	1 },
#endif
	{ NULL,		NULL,		0 }
};


int findscan(const void *key1, const void *key2) {
        const scaninfo *chan1 = key1;
        return (strcasecmp(chan1->who, key2));
}

int ports_sort(const void *key1, const void *key2) {
	port_list *pl1 = (port_list *)key1;
	port_list *pl2 = (port_list *)key2;
	if (pl1->type == pl2->type) {
		if (pl1->port == pl2->port) {
			return 0;
		} else if (pl1->port > pl2->port) {
			return 1;
		} else {
			return -1;
		}
	} else if (pl1->type > pl2->type) {
		return 1;
	} else {
		return -1;
	}
}


int __BotMessage(char *origin, char **argv, int argc)
{
	User *u, *u2;
	lnode_t *lnode;
	scaninfo *scandata;
	exemptinfo *exempts;
	port_list *pl;
	int lookuptype, i;
	char *buf;

	SET_SEGV_LOCATION();
	
	u = finduser(origin); 
	if (!u) { 
		nlog(LOG_WARNING, LOG_MOD, "Unable to find user %s (opsb)", origin); 
		return -1; 
	} 
	if (!strcasecmp(argv[1], "help")) {
		if (argc == 2) {
			privmsg_list(u->nick, s_opsb, opsb_help);
			if (UserLevel(u) >= NS_ULEVEL_OPER)
				privmsg_list(u->nick, s_opsb, opsb_help_oper);
			privmsg_list(u->nick, s_opsb, opsb_help_on_help);			
		} else if (!strcasecmp(argv[2], "lookup")) {
				privmsg_list(u->nick, s_opsb, opsb_help_lookup);
		} else if (!strcasecmp(argv[2], "info")) {
				privmsg_list(u->nick, s_opsb, opsb_help_info);
		} else if ((!strcasecmp(argv[2], "check") && UserLevel(u) >= NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_opsb, opsb_help_check);
		} else if ((!strcasecmp(argv[2], "status") && UserLevel(u) >= NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_opsb, opsb_help_status);
		} else if ((!strcasecmp(argv[2], "set") && UserLevel(u) >= 100)) {
				privmsg_list(u->nick, s_opsb, opsb_help_set);
		} else if ((!strcasecmp(argv[2], "ports") && UserLevel(u) >= 100)) {
				privmsg_list(u->nick, s_opsb, opsb_help_ports);
		} else if ((!strcasecmp(argv[2], "exclude") && UserLevel(u) > 100)) {
				privmsg_list(u->nick, s_opsb, opsb_help_exclude);
		} else if ((!strcasecmp(argv[2], "remove") && UserLevel(u) > NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_opsb, opsb_help_remove);
		} else {
			prefmsg(u->nick, s_opsb, "Invalid Syntax. /msg %s help for more info", s_opsb);
		}
		return 1;
	} else if (!strcasecmp(argv[1], "info")) {
		privmsg_list(u->nick, s_opsb, opsb_help_info);
		return 1;
	} else if (!strcasecmp(argv[1], "status")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_opsb, "Access Denied");
			chanalert(s_opsb, "%s tried to view status, but is not an operator", u->nick);
			return 1;
		}
		send_status(u);
		return 1;
	} else if (!strcasecmp(argv[1], "lookup")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_opsb, "Access Denied");
			chanalert(s_opsb, "%s tried to use lookup, but is not an operator", u->nick);
			return 1;
		}
		if (argc < 3) {
			prefmsg(u->nick, s_opsb, "Invalid Syntax. /msg %s help lookup for more help", s_opsb);
			return 0;
		}
		scandata = malloc(sizeof(scaninfo));
		scandata->dnsstate = REPORT_DNS;
		strlcpy(scandata->who, u->nick, MAXNICK);
		strlcpy(scandata->lookup, argv[2], MAXHOST);
		/* if the lists are full, don't add it, and alert the user */
		if (list_isfull(opsbl)) {
			if (list_isfull(opsbq)) {
				prefmsg(u->nick, s_opsb, "Too Busy. Try again Later");
				free(scandata);
				return 0;
			}
			prefmsg(u->nick, s_opsb, "OPSB list is full, queuing your request");
			lnode = lnode_create(scandata);
			list_append(opsbq, lnode);
		}
		if (inet_aton(scandata->lookup, NULL) > 0) {
			lookuptype = adns_r_ptr;
		} else {
			if (argc == 4) {
				if (!strcasecmp(argv[3], "txt"))
					lookuptype = adns_r_txt;
				else if (!strcasecmp(argv[3], "rp"))
					lookuptype = adns_r_rp;
				else if (!strcasecmp(argv[3], "ns"))
					lookuptype = adns_r_ns;
				else if (!strcasecmp(argv[3], "soa"))
					lookuptype = adns_r_soa;
				else 
					lookuptype = adns_r_a;
			} else {
				lookuptype = adns_r_a;
			}
		}
		if (dns_lookup(scandata->lookup, lookuptype, reportdns, scandata->who) != 1) {
			prefmsg(u->nick, s_opsb, "DnsLookup Failed.");
			free(scandata);
			return 0;
		} 
		lnode = lnode_create(scandata);
		list_append(opsbl, lnode);
	} else if (!strcasecmp(argv[1], "remove")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_opsb, "Access Denied");
			chanalert(s_opsb, "%s tried to use remove, but does not have access", u->nick);
			return 0;
		}
		if (argc < 3) {
			prefmsg(u->nick, s_opsb, "Invalid Syntax. /msg %s help remove for more info", s_opsb);
			return 0;
		}
		srakill_cmd(argv[2], "*");
		chanalert(s_opsb, "%s attempted to remove an akill for *@%s", u->nick, argv[2]);
		return 1;
	} else if (!strcasecmp(argv[1], "check")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_opsb, "Access Denied");
			chanalert(s_opsb, "%s tried to use check, but does not have access", u->nick);
			return 0;
		}
		if (argc < 3) {
			prefmsg(u->nick, s_opsb, "Invalid Syntax. /msg %s help check for more info", s_opsb);
			return 0;
		}
		if ((list_find(opsbl, argv[2], findscan)) || (list_find(opsbq, argv[2], findscan))) {
			prefmsg(u->nick, s_opsb, "Already Scanning (or in queue) %s. Not Scanning again", argv[2]);
			return 0;
		}
		scandata = malloc(sizeof(scaninfo));
		scandata->doneban = 0;
		scandata->u = u;
		if ((u2 = finduser(argv[2])) != NULL) {
			/* don't scan users from my server */
			if (!strcasecmp(u2->server->name, me.name)) {
				prefmsg(u->nick, s_opsb, "Error, Can not scan NeoStats Bots");
				return -1;
			}
			strlcpy(scandata->who, u2->nick, MAXHOST);
			strlcpy(scandata->lookup, u2->hostname, MAXHOST);
			strlcpy(scandata->server, u2->server->name, MAXHOST);
			scandata->ipaddr.s_addr = u2->ipaddr.s_addr;
			if (scandata->ipaddr.s_addr > 0) {
				scandata->dnsstate = DO_OPM_LOOKUP;
			} else {
				if (inet_aton(u2->hostname, &scandata->ipaddr) > 0)
					scandata->dnsstate = DO_OPM_LOOKUP;
				else {
					scandata->dnsstate = GET_NICK_IP;
					scandata->ipaddr.s_addr = 0;
				}
			}
		} else {
			strlcpy(scandata->who, argv[2], MAXHOST);
			strlcpy(scandata->lookup, argv[2], MAXHOST);
			bzero(scandata->server, MAXHOST);
			if (inet_aton(argv[2], &scandata->ipaddr) > 0) {
				scandata->dnsstate = DO_OPM_LOOKUP;
			} else {
				scandata->dnsstate = GET_NICK_IP;
				scandata->ipaddr.s_addr = 0;
			}
		}
		prefmsg(u->nick, s_opsb, "Checking %s for open Proxies", argv[2]);
		if (!startscan(scandata)) 
			prefmsg(u->nick, s_opsb, "Check Failed");
		
		return 1;
	} else if (!strcasecmp(argv[1], "EXCLUDE")) {
		if (UserLevel(u) < 50) {
			prefmsg(u->nick, s_opsb, "Access Denied");
			chanalert(s_opsb, "%s tried to use exclude, but is not an operator", u->nick);
			return 1;
		}
		if (argc < 3) {
			prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help exclude", s_opsb);
			return 0;
		}
		if (!strcasecmp(argv[2], "LIST")) {
			lnode = list_first(exempt);
			i = 1;
			prefmsg(u->nick, s_opsb, "Exception List:");
			while (lnode) {
				exempts = lnode_get(lnode);
				prefmsg(u->nick, s_opsb, "%d) %s %s Added by %s for %s", i, exempts->host, (exempts->server ? "(Server)" : "(Client)"), exempts->who, exempts->reason);
				++i;
				lnode = list_next(exempt, lnode);
			}
			prefmsg(u->nick, s_opsb, "End of List.");
			chanalert(s_opsb, "%s requested Exception List", u->nick);
		} else if (!strcasecmp(argv[2], "ADD")) {
			if (argc < 6) {
				prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help exclude", s_opsb);
				return 0;
			}
			if (list_isfull(exempt)) {
				prefmsg(u->nick, s_opsb, "Error, Exception list is full");
				return 0;
			}
			if (!index(argv[3], '.')) {
				prefmsg(u->nick, s_opsb, "Host field does not contain a vaild host");
				return 0;
			}
			exempts = malloc(sizeof(exemptinfo));
			strlcpy(exempts->host, argv[3], MAXHOST);
			if (atoi(argv[4]) > 0)
				exempts->server = 1;
			else 
				exempts->server = 0;
			strlcpy(exempts->who, u->nick, MAXNICK);
			buf = joinbuf(argv, argc, 5);
			strlcpy(exempts->reason, buf, MAXHOST);
			free(buf);
			lnode = lnode_create(exempts);
			list_append(exempt, lnode);
			save_exempts(exempts);			

			prefmsg(u->nick, s_opsb, "Added %s (%s) exception to list", exempts->host, (exempts->server ? "(Server)" : "(Client)"));
			chanalert(s_opsb, "%s added %s (%s) exception to list", u->nick, exempts->host, (exempts->server ? "(Server)" : "(Client)"));
		} else if (!strcasecmp(argv[2], "DEL")) {
			if (argc < 3) {
				prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help exclude", s_opsb);
				return 0;
			}
			if (atoi(argv[3]) != 0) {
				lnode = list_first(exempt);
				i = 1;
				while (lnode) {
					if (i == atoi(argv[3])) {
						/* delete the entry */
						exempts = lnode_get(lnode);
						buf = malloc(512);
						ircsnprintf(buf, 512, "Exempt/%s", exempts->host);
						DelConf(buf);
						free(buf);
						list_delete(exempt, lnode);
						prefmsg(u->nick, s_opsb, "Deleted %s %s out of exception list", exempts->host, (exempts->server ? "(Server)" : "(Client)"));
						chanalert(s_opsb, "%s deleted %s %s out of exception list", u->nick, exempts->host, (exempts->server ? "(Server)" : "(Client)"));
						free(exempts);
						return 1;
					}
					++i;
					lnode = list_next(exempt, lnode);
				}		
				/* if we get here, then we can't find the entry */
				prefmsg(u->nick, s_opsb, "Error, Can't find entry %d. /msg %s exclude list", atoi(argv[3]), s_opsb);
				return 0;
			} else {
				prefmsg(u->nick, s_opsb, "Error, Out of Range");
				return 0;
			}
		} else {
			prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help exclude", s_opsb);
			return 0;
		}
	} else if (!strcasecmp(argv[1], "PORTS")) {
		if (UserLevel(u) < 100) {
			prefmsg(u->nick, s_opsb, "Access Denied");
			chanalert(s_opsb, "%s tried to use ports, but is not an operator", u->nick);
			return 1;
		}
		if (argc < 3) {
			prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help ports", s_opsb);
			return 0;
		}
		if (!strcasecmp(argv[2], "LIST")) {
			lnode = list_first(opsb.ports);
			i = 1;
			prefmsg(u->nick, s_opsb, "Port List:");
			while (lnode) {
				pl = lnode_get(lnode);
				prefmsg(u->nick, s_opsb, "%d) %s Port: %d", i, type_of_proxy(pl->type), pl->port);
				++i;
				lnode = list_next(opsb.ports, lnode);
			}
			prefmsg(u->nick, s_opsb, "End of List.");
			chanalert(s_opsb, "%s requested Port List", u->nick);
		} else if (!strcasecmp(argv[2], "ADD")) {
			if (argc < 5) {
				prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help ports", s_opsb);
				return 0;
			}
			if (list_isfull(opsb.ports)) {
				prefmsg(u->nick, s_opsb, "Error, Ports list is full");
				return 0;
			}
			if (!atoi(argv[4])) {
				prefmsg(u->nick, s_opsb, "Port field does not contain a vaild port");
				return 0;
			}
			if (get_proxy_by_name(argv[3]) < 1) {
				prefmsg(u->nick, s_opsb, "Unknown Proxy type %s", argv[3]);
				return 0;
			}
			/* check for duplicates */
			lnode = list_first(opsb.ports);
			while (lnode) {
				pl = lnode_get(lnode);
				if ((pl->type == get_proxy_by_name(argv[3])) && (pl->port == atoi(argv[4]))) {
					prefmsg(u->nick, s_opsb, "Duplicate Entry for Protocol %s", argv[3]);
					return 0;
				}
				lnode = list_next(opsb.ports, lnode);
			}
			pl = malloc(sizeof(port_list));
			pl->type = get_proxy_by_name(argv[3]);
			pl->port = atoi(argv[4]);
				
			lnode = lnode_create(pl);
			list_append(opsb.ports, lnode);
			list_sort(opsb.ports, ports_sort);
			save_ports();
			add_port(pl->type, pl->port);
			prefmsg(u->nick, s_opsb, "Added Port %d for Protocol %s to Ports list", pl->port, argv[3]);
			chanalert(s_opsb, "%s added port %d for protocol %s to Ports list", u->nick, pl->port, argv[3]);
		} else if (!strcasecmp(argv[2], "DEL")) {
			if (argc < 3) {
				prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help ports", s_opsb);
				return 0;
			}
			if (atoi(argv[3]) != 0) {
				lnode = list_first(opsb.ports);
				i = 1;
				while (lnode) {
					if (i == atoi(argv[3])) {
						/* delete the entry */
						pl = lnode_get(lnode);
						list_delete(opsb.ports, lnode);
						prefmsg(u->nick, s_opsb, "Deleted Port %d of Protocol %s out of Ports list", pl->port, type_of_proxy(pl->type));
						prefmsg(u->nick, s_opsb, "You need to Restart OPSB for the changes to take effect");
						chanalert(s_opsb, "%s deleted port %d of Protocol %s out of Ports list", u->nick, pl->port, type_of_proxy(pl->type));
						free(pl);
						/* just to be sure, lets sort the list */
						list_sort(opsb.ports, ports_sort);
						save_ports();
						return 1;
					}
					++i;
					lnode = list_next(opsb.ports, lnode);
				}		
				/* if we get here, then we can't find the entry */
				prefmsg(u->nick, s_opsb, "Error, Can't find entry %d. /msg %s ports list", atoi(argv[3]), s_opsb);
				return 0;
			} else {
				prefmsg(u->nick, s_opsb, "Error, Out of Range");
				return 0;
			}
		} else {
			prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help ports", s_opsb);
			return 0;
		}
	} else if (!strcasecmp(argv[1], "SET")) {
		if (argc < 3) {
			prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help set", s_opsb);
			return 0;
		}
		do_set(u, argv, argc);
		SetConf((void *)opsb.confed, CFGINT, "Confed");

	} else {
		prefmsg(u->nick, s_opsb, "Syntax Error. /msg %s help", s_opsb);
	}
	return 1;
}

int do_set(User *u, char **av, int ac) {
	char *buf;

	SET_SEGV_LOCATION();
	
	if (UserLevel(u) < 100) {
		prefmsg(u->nick, s_opsb, "Access Denied");
		chanalert(s_opsb, "%s tried to set, but doesn't have access", u->nick);
		return 0;
	}

	if (!strcasecmp(av[2], "DISABLESCAN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
	 	if (!strcasecmp(av[3], "0") || !strcasecmp(av[3], "off")) {
			opsb.doscan = 1;
			prefmsg(u->nick, s_opsb, "Scanning is now Enabled");
			chanalert(s_opsb, "%s has Enabled Proxy Scanning", u->nick);
		} else if (!strcasecmp(av[3], "1") || !strcasecmp(av[3], "on")) {
			opsb.doscan = 0;
			prefmsg(u->nick, s_opsb, "Scanning is now Disabled");
			chanalert(s_opsb, "%s has Disabled Proxy Scanning", u->nick);
		} else {
			prefmsg(u->nick, s_opsb, "Invalid Setting (must be 1 or 0) in DISABLESCAN");
			return 0;
		}
		SetConf((void *)opsb.doscan, CFGINT, "DoScan");
		opsb.confed = 1;
		return 1;
	} else if (!strcasecmp(av[2], "DOBAN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
	 	if (!strcasecmp(av[3], "0") || !strcasecmp(av[3], "off")) {
			opsb.doban = 0;
			prefmsg(u->nick, s_opsb, "Akill Bans for Open Proxies is now Disabled");
			chanalert(s_opsb, "%s has Disabled Akills for Open Proxys", u->nick);
		} else if (!strcasecmp(av[3], "1") || !strcasecmp(av[3], "on")) {
			opsb.doban = 1;
			prefmsg(u->nick, s_opsb, "Akill Bans for Open Proxies is now Enabled");
			chanalert(s_opsb, "%s has Enabled Akills for Open Proxies", u->nick);
		} else {
			prefmsg(u->nick, s_opsb, "Invalid Setting (must be 1 or 0) in DOBAN");
			return 0;
		}
		SetConf((void *)opsb.doban, CFGINT, "DoBan");
		opsb.confed = 1;
		return 1;
	} else if (!strcasecmp(av[2], "TARGETIP")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		if (!inet_addr(av[3])) {
			prefmsg(u->nick, s_opsb, "Invalid IP address (Can not be hostname) in TARGETIP");
			return 0;
		}
		strlcpy(opsb.targethost, av[3], MAXHOST);
		prefmsg(u->nick, s_opsb, "Target IP set to %s", av[3]);
		chanalert(s_opsb, "%s changed the target ip to %s", u->nick, av[3]);
		SetConf((void *)opsb.targethost, CFGSTR, "TargetHost");
		opsb.confed = 1;
		return 1;
	} else if (!strcasecmp(av[2], "TARGETPORT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		if (!atoi(av[3])) {
			prefmsg(u->nick, s_opsb, "Invalid Port (Must be numeric) in TARGETPORT");
			return 0;
		}
		opsb.targetport = atoi(av[3]);
		prefmsg(u->nick, s_opsb, "Target PORT set to %d", opsb.targetport);
		chanalert(s_opsb, "%s changed the target port to %d", u->nick, opsb.targetport);
		SetConf((void *)opsb.targetport, CFGINT, "TargetPort");
		opsb.confed = 1;
		return 1;
	} else if (!strcasecmp(av[2], "OPMDOMAIN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		if (!index(av[3], '.')) {
			prefmsg(u->nick, s_opsb, "Invalid Domain name in OPMDOMAIN");
			return 0;
		}
		strlcpy(opsb.opmdomain, av[3], MAXHOST);
		prefmsg(u->nick, s_opsb, "OPM Domain changed to %s", opsb.opmdomain);
		chanalert(s_opsb, "%s changed the opm domain to %s", u->nick, opsb.opmdomain);
		SetConf((void *)opsb.opmdomain, CFGSTR, "OpmDomain");
		opsb.confed = 1;
		return 1;
	} else if (!strcasecmp(av[2], "MAXBYTES")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		if (!atoi(av[3])) {
			prefmsg(u->nick, s_opsb, "Invalid setting (Must be numeric)");
			return 0;
		} 
		opsb.maxbytes = atoi(av[3]);
		prefmsg(u->nick, s_opsb, "Max Bytes set to %d", opsb.maxbytes);
		chanalert(s_opsb, "%s changed the Max Bytes setting to %d", u->nick, opsb.maxbytes);
		SetConf((void *)opsb.maxbytes, CFGINT, "MaxBytes");
		opsb.confed = 1;
		return 1;
	} else if (!strcasecmp(av[2], "TIMEOUT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		if (!atoi(av[3]) || (atoi(av[3]) > 120)) {
			prefmsg(u->nick, s_opsb, "Setting must be numeric, and below 120");
			return 0;
		}
		opsb.timeout = atoi(av[3]);
		prefmsg(u->nick, s_opsb, "Timeout set to %d", opsb.timeout);
		chanalert(s_opsb, "%s changed the timeout to %d", u->nick, opsb.timeout);
		SetConf((void *)opsb.timeout, CFGINT, "TimeOut");
		opsb.confed = 1;
		return 1;
	} else if (!strcasecmp(av[2], "OPENSTRING")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		buf = joinbuf(av, ac, 3);
		strlcpy(opsb.lookforstring, buf, 512);
		free(buf);
		prefmsg(u->nick, s_opsb, "OPENSTRING changed to %s", opsb.lookforstring);
		chanalert(s_opsb, "%s changed OPENSTRING to %s", u->nick, opsb.lookforstring);
		SetConf((void *)opsb.lookforstring, CFGSTR, "TriggerString");
		opsb.confed = 1;
		return 0;
	} else if (!strcasecmp(av[2], "SPLITTIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		if (!atoi(av[3])) {
			prefmsg(u->nick, s_opsb, "Error, Setting must be numeric");
			return 0;
		}
		opsb.timedif = atoi(av[3]);
		prefmsg(u->nick, s_opsb, "SPLITTIME changed to %d", opsb.timedif);
		chanalert(s_opsb, "%s changed the split time to %d", u->nick, opsb.timedif);
		SetConf((void *)opsb.timedif, CFGINT, "SplitTime");
		opsb.confed = 1;
		return 0;
	} else if (!strcasecmp(av[2], "SCANMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		buf = joinbuf(av, ac, 3);
		strlcpy(opsb.scanmsg, buf, 512);
		free(buf);
		prefmsg(u->nick, s_opsb, "ScanMessage changed to %s", opsb.scanmsg);
		chanalert(s_opsb, "%s changed the scan message to %s", u->nick, opsb.scanmsg);
		SetConf((void *)opsb.scanmsg, CFGSTR, "ScanMsg");
		opsb.confed = 1;
		return 0;
	} else if (!strcasecmp(av[2], "BANTIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		if (!atoi(av[3])) {
			prefmsg(u->nick, s_opsb, "Error, Bantime must be numeric (in Seconds)");
			return 0;
		}
		opsb.bantime = atoi(av[3]);
		prefmsg(u->nick, s_opsb, "Ban time changed to %d", opsb.bantime);
		chanalert(s_opsb, "%s changed ban time to %d", u->nick, opsb.bantime);
		SetConf((void *)opsb.bantime, CFGINT, "BanTime");
		opsb.confed = 1;
		return 0;
	} else if (!strcasecmp(av[2], "CACHETIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_opsb, "Invalid Option. Try /msg %s help set", s_opsb);
			return 0;
		}
		if (!atoi(av[3])) {
			prefmsg(u->nick, s_opsb, "Error, CacheTime must be numeric (in Seconds)");
			return 0;
		}
		opsb.cachetime = atoi(av[3]);
		prefmsg(u->nick, s_opsb, "CacheTime set to %d", opsb.cachetime);
		chanalert(s_opsb, "%s changed cachetime to %d", u->nick, opsb.cachetime);
		SetConf((void *)opsb.cachetime, CFGINT, "CacheTime");
		opsb.confed = 1;
		return 0;
	} else if (!strcasecmp(av[2], "LIST")) {
		prefmsg(u->nick, s_opsb, "Proxy Scanning: %s", opsb.doscan == 1 ? "Yes" : "No");
		prefmsg(u->nick, s_opsb, "Akill for Open Proxy: %s", opsb.doban == 1 ? "Yes" : "No");
		prefmsg(u->nick, s_opsb, "TargetIP: %s", opsb.targethost);
		prefmsg(u->nick, s_opsb, "TargetPort: %d", opsb.targetport);
		prefmsg(u->nick, s_opsb, "OPM Domain: %s", opsb.opmdomain);
		prefmsg(u->nick, s_opsb, "Max Bytes: %d", opsb.maxbytes);
		prefmsg(u->nick, s_opsb, "TimeOut: %d", opsb.timeout);
		prefmsg(u->nick, s_opsb, "Target String: %s", opsb.lookforstring);
		prefmsg(u->nick, s_opsb, "Split Time: %d", opsb.timedif);
		prefmsg(u->nick, s_opsb, "ScanMessage: %s", opsb.scanmsg);
		prefmsg(u->nick, s_opsb, "Ban Time: %d", opsb.bantime);
		prefmsg(u->nick, s_opsb, "Cache Time: %d", opsb.cachetime);
		prefmsg(u->nick, s_opsb, "Configured: %s", (opsb.confed ? "Yes" : "No"));
		return 0;
	} else {
		prefmsg(u->nick, s_opsb, "Unknown Command %s, try /msg %s help set", av[2], s_opsb);
		return 0;
	}
	return 0;	
}

static int Online(char **av, int ac) {
	struct sockaddr_in sa;
	socklen_t ulen = sizeof(struct sockaddr_in);

	SET_SEGV_LOCATION();

	if (init_bot(s_opsb,"opsb",me.name,"Proxy Scanning Bot", "+S", __module_info.module_name) == -1 ) {
		/* Nick was in use!!!! */
		strlcat(s_opsb, "_", MAXNICK);
		init_bot(s_opsb,"opsb",me.name,"Proxy Scanning Bot", "+S", __module_info.module_name);
	}
	if (opsb.confed == 0) {
		add_mod_timer("unconf", "Un_configured_warn", "opsb", 60);
		unconf();
		getpeername(servsock, (struct sockaddr *)&sa, (socklen_t*)&ulen);
		strlcpy(opsb.targethost, inet_ntoa(sa.sin_addr), MAXHOST);
	}
	if (opsb.doscan) {
		chanalert(s_opsb, "Open Proxy Scanning bot has started (Concurrent Scans: %d Sockets %d)", opsb.socks, opsb.socks *7);
	} else {
		chanalert(s_opsb, "DNS Blacklist Lookup is only Enabled!! (No Open Proxy Scans)");
	}
	online = 1;
	return 1;
};


void unconf() {
	if (opsb.confed == 1) return;
	chanalert(s_opsb, "Warning, OPSB is configured with default Settings. Please Update this ASAP");
	globops(s_opsb, "Warning, OPSB is configured with default Settings, Please Update this ASAP");
}

void save_ports() {
	lnode_t *pn;
	port_list *pl;
	char confpath[CONFBUFSIZE];
	char ports[CONFBUFSIZE];
	char tmpports[CONFBUFSIZE];
	int lasttype = -1;
	pn = list_first(opsb.ports);
	while (pn) {
		pl = lnode_get(pn);
		/* if the port is different from the last round, and its not the first round, save it */
		if ((pl->type != lasttype) && (lasttype != -1)) {
			strlcpy(confpath, type_of_proxy(lasttype), CONFBUFSIZE);
			SetConf((void *)ports, CFGSTR, confpath);
		} 
		if (pl->type != lasttype) {
			ircsnprintf(ports, CONFBUFSIZE, "%d", pl->port);
		} else {
			ircsnprintf(tmpports, CONFBUFSIZE, "%s %d", ports, pl->port);
			strlcpy(ports, tmpports, CONFBUFSIZE);
		}
		lasttype = pl->type;
		pn = list_next(opsb.ports, pn);
	}
	strlcpy(confpath, type_of_proxy(lasttype), CONFBUFSIZE);
	SetConf((void *)ports, CFGSTR, confpath);
	flush_keeper();
} 



void checkqueue() {
	lnode_t *scannode;
	scaninfo *scandata;

	SET_SEGV_LOCATION();
	
	/* exit, if the list is full */
	if (list_isfull(opsbl) || list_isempty(opsbq))
		return;
	
	scannode = list_first(opsbq);
	scandata = lnode_get(scannode);
	list_delete(opsbq, scannode);
	lnode_destroy(scannode);
	startscan(scandata);

}

void addtocache(unsigned long ipaddr) {
	lnode_t *cachenode;
	C_entry *ce;

	SET_SEGV_LOCATION();
			
	/* pop off the oldest entry */
	if (list_isfull(cache)) {
		nlog(LOG_DEBUG2, LOG_MOD, "OPSB: Deleting Tail of Cache: %d", (int)list_count(cache));
		cachenode = list_del_last(cache);
		ce = lnode_get(cachenode);
		lnode_destroy(cachenode);
		free(ce);
	}
	cachenode = list_first(cache);
	while (cachenode) {
		ce = lnode_get(cachenode);
		if (ce->ip == ipaddr) {
			nlog(LOG_DEBUG2, LOG_MOD,"OPSB: Not adding %ld to cache as it already exists", ipaddr);
			return;
		}
		cachenode = list_next(cache, cachenode);
	}
	
	ce = malloc(sizeof(C_entry));
	ce->ip = ipaddr;
	ce->when = time(NULL);
	cachenode = lnode_create(ce);
	list_prepend(cache, cachenode);
}

int checkcache(scaninfo *scandata) {
	lnode_t *node, *node2;
	C_entry *ce;
	exemptinfo *exempts;

	SET_SEGV_LOCATION();

	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if ((exempts->server == 1) && (scandata->server)) {
			/* match a server */
			if (fnmatch(exempts->host, scandata->server, 0) == 0) {
				nlog(LOG_DEBUG1, LOG_MOD, "OPSB: User %s exempt. Matched server entry %s in Exemptions", scandata->who, exempts->host);
				if (scandata->u) prefmsg(scandata->u->nick, s_opsb,"%s Matches a Server Exception %s", scandata->who, exempts->host);
				return 1;
			}
		} else {
			if (fnmatch(exempts->host, scandata->lookup, 0) == 0) {
				nlog(LOG_DEBUG1, LOG_MOD, "OPSB: User %s exempt. Matched host entry %s in exemptions", scandata->who, exempts->host);
				if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "%s Matches a Host Exception %s", scandata->who, exempts->host);
				return 2;
			}
		}
	node = list_next(exempt, node);
	}
	node = list_first(cache);
	while (node) {
		ce = lnode_get(node);
		
		/* delete any old cache entries */
	
		if ((time(NULL) - ce->when) > opsb.cachetime) {
			nlog(LOG_DEBUG1, LOG_MOD, "OPSB: Deleting old cache entry %ld", ce->ip);
			node2 = list_next(cache, node);			
			list_delete(cache, node);
			lnode_destroy(node);
			free(ce);
			node = node2;
			break;
		}
		if (ce->ip == scandata->ipaddr.s_addr) {
			nlog(LOG_DEBUG1, LOG_MOD, "OPSB: user %s is already in Cache", scandata->who);
			opsb.cachehits++;
			if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "User %s is already in Cache", scandata->who);
			return 3;
		}
	node = list_next(cache, node);
	}
	return 0;
}


EventFnList __module_events[] = {
	{ EVENT_ONLINE, 	Online},
	{ EVENT_SIGNON, 	ScanNick},
	{ NULL, 	NULL}
};

/* this function kicks of a scan of a user that just signed on the network */
static int ScanNick(char **av, int ac) {
	User *u;
	scaninfo *scandata;
	lnode_t *scannode;
	lnode_t *node;
	exemptinfo *exempts;

	SET_SEGV_LOCATION();

	/* don't do anything if NeoStats hasn't told us we are online yet */
	if (!online)
		return 0;
							
	u = finduser(av[0]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "OPSB: Ehhh, Can't find user %s", av[0]);
		return -1;
	}
	
	/* don't scan users from my own server */
	if (!strcasecmp(u->server->name, me.name)) {
		return -1;
	}

	/* don't scan users from a server that is excluded */
	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->server == 1) {
			/* match a server */
			if (fnmatch(exempts->host, u->server->name, 0) == 0) {
				nlog(LOG_DEBUG1, LOG_MOD, "OPSB: User %s exempt. Matched server entry %s in Exemptions", u->nick, exempts->host);
				return -1;
			}
		}
		node = list_next(exempt, node);
	}

	if (time(NULL) - u->TS > opsb.timedif) {
		nlog(LOG_DEBUG1, LOG_MOD, "Netsplit Nick %s, Not Scanning", av[0]);
		return -1;
	}

	scannode = list_find(opsbl, av[0], findscan);
	if (!scannode) scannode = list_find(opsbq, av[0], findscan);
	if (scannode) {
		nlog(LOG_DEBUG1, LOG_MOD, "ScanNick(): Not scanning %s as we are already scanning them", av[0]);
		return -1;
	}
	prefmsg(u->nick, s_opsb, "%s", opsb.scanmsg);
	scandata = malloc(sizeof(scaninfo));
	scandata->u = NULL;
	scandata->doneban = 0;
	strlcpy(scandata->who, u->nick, MAXHOST);
	strlcpy(scandata->lookup, u->hostname, MAXHOST);
	strlcpy(scandata->server, u->server->name, MAXHOST);
	strlcpy(scandata->connectstring, recbuf, BUFSIZE);
	scandata->ipaddr.s_addr = u->ipaddr.s_addr;
	if (scandata->ipaddr.s_addr > 0) {
		scandata->dnsstate = DO_OPM_LOOKUP;
	} else {
		if (inet_aton(u->hostname, &scandata->ipaddr) > 0)
			scandata->dnsstate = DO_OPM_LOOKUP;
		else {
			scandata->dnsstate = GET_NICK_IP;
			scandata->ipaddr.s_addr = 0;
		}
	}
	if (!startscan(scandata)) {
		chanalert(s_opsb, "Warning Can't scan %s", u->nick);
		nlog(LOG_WARNING, LOG_MOD, "OBSB ScanNick(): Can't scan %s. Check logs for possible errors", u->nick);
	}
	return 1;


}



/* this function is the entry point for all scans. Any scan you want to kick off is started with this function. */
/* this includes moving scans from the queue to the active list */

int startscan(scaninfo *scandata) {
	lnode_t *scannode;
	unsigned char a, b, c, d;
	char *buf;
	int buflen;
	int i;

	SET_SEGV_LOCATION();
	
	/* only check the cache when we have IP addy */
	if (scandata->dnsstate == DO_OPM_LOOKUP) {
		i = checkcache(scandata);
		if ((i > 0) && (scandata->u == NULL)) {
			free(scandata);
			return 1;
		}
	}
	switch(scandata->dnsstate) {
		case GET_NICK_IP:
				if (list_isfull(opsbl)) {
					if (list_isfull(opsbq)) {
						chanalert(s_opsb, "Warning, Both Current and queue lists are full. Not Adding additional scans");
						nlog(LOG_DEBUG1, LOG_MOD, "OPSB: dropped scaning of %s, as queue is full", scandata->who);
						if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "To Busy. Try again later");
						free(scandata);
						return 0;
					}
					scannode = lnode_create(scandata);
					list_append(opsbq, scannode);
					nlog(LOG_DEBUG1, LOG_MOD, "DNS: Added %s to dns queue", scandata->who);
					if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Your Request has been added to the Queue");
					return 1;
				}
				if (dns_lookup(scandata->lookup, adns_r_a, dnsblscan, scandata->who) != 1) {
					nlog(LOG_WARNING, LOG_MOD, "DNS: startscan() GET_NICK_IP dns_lookup() failed");
					free(scandata);
					checkqueue();
					return 0;
				}

				scannode = lnode_create(scandata);
				list_append(opsbl, scannode);
				nlog(LOG_DEBUG1, LOG_MOD, "DNS: Added getnickip to DNS active list");
				return 1;		
				break;
		case DO_OPM_LOOKUP:
				if (list_isfull(opsbl)) {
					if(list_isfull(opsbq)) {
						chanalert(s_opsb, "Warning, Both Current and Queue lists are full, Not adding Scan");
						if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Too Busy. Try again Later");
						free(scandata);
						return 0;
					}
					scannode = lnode_create(scandata);
					list_append(opsbq, scannode);
					nlog(LOG_DEBUG1, LOG_MOD, "DNS: Added OPM lookup to queue: %s", scandata->who);
					return 1;
				}
        			d = (unsigned char) (scandata->ipaddr.s_addr >> 24) & 0xFF;
                		c = (unsigned char) (scandata->ipaddr.s_addr >> 16) & 0xFF;
                        	b = (unsigned char) (scandata->ipaddr.s_addr >> 8) & 0xFF;
                                a = (unsigned char) scandata->ipaddr.s_addr & 0xFF;
                                
                                /* Enough for a reversed IP and the zone. */
                                buflen = 18 + strlen(opsb.opmdomain);
                                buf = malloc(buflen * sizeof(*buf));
                                                     
                                ircsnprintf(buf, buflen, "%d.%d.%d.%d.%s", d, c, b, a, opsb.opmdomain);
				if (dns_lookup(buf, adns_r_a, dnsblscan, scandata->who) != 1) {
					nlog(LOG_WARNING, LOG_MOD, "DNS: startscan() DO_OPM_LOOKUP dns_lookup() failed");
					free(scandata);
					free(buf);
					checkqueue();
					return 0;
				}
				scannode = lnode_create(scandata);
				list_append(opsbl, scannode);
				nlog(LOG_DEBUG1, LOG_MOD, "DNS: Added OPM %s lookup to DNS active list", buf);
				free(buf);
				start_proxy_scan(scannode);
				++opsb.scanned;
				return 1;
				break;
		default:
				nlog(LOG_WARNING, LOG_MOD, "Warning, Unknown Status in startscan()");
				free(scandata);
				return -1;
	}
}

/* this function is called when either checking the opm list, or when we are trying to resolve the hostname */

void dnsblscan(char *data, adns_answer *a) {
	lnode_t *scannode;
	scaninfo *scandata;
	char *show;
	int len, ri;

	SET_SEGV_LOCATION();

	scannode = list_find(opsbl, data, findscan);
	if (!scannode) {
		nlog(LOG_CRITICAL, LOG_MOD, "dnsblscan(): Ehhh, Something is wrong here - Can't find %s", data);
		return;
	}
	scandata = lnode_get(scannode);
	if (a) {
		switch(scandata->dnsstate) {
			case GET_NICK_IP:
					if (a->nrrs < 1) {
						chanalert(s_opsb, "No Record for %s. Aborting Scan", scandata->lookup);
						if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "No A record for %s. Aborting Scan", scandata->lookup);
						list_delete(opsbl, scannode);
						lnode_destroy(scannode);
						free(scandata);
						checkqueue();
						break;
					}
					adns_rr_info(a->type, 0, 0, &len, 0, 0);
					ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes, &show);
					if (!ri) {
						nlog(LOG_DEBUG1, LOG_MOD, "DNS: Got IP for %s -> %s", scandata->who, show);
						if (a->nrrs > 1) {
							chanalert(s_opsb, "Warning, More than one IP address for %s. Using %s only", scandata->lookup, show);
							if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Warning, More than one IP address for %s. Using %s only", scandata->lookup, show);
						}
						if (inet_aton(show, &scandata->ipaddr) > 0) {
							scandata->dnsstate = DO_OPM_LOOKUP;
							list_delete(opsbl, scannode);
							lnode_destroy(scannode);
							startscan(scandata);
						} else {
							nlog(LOG_CRITICAL, LOG_MOD, "DNS: dnsblscan() GETNICKIP failed-> %s", show);
							chanalert(s_opsb, "Warning, Couldn't get the address for %s", scandata->who);
					        	list_delete(opsbl, scannode);
			        			lnode_destroy(scannode);
			        			free(scandata);
							checkqueue();
						}

					} else {
						nlog(LOG_CRITICAL, LOG_MOD, "DNS: dnsblscan GETNICKIP rr_info failed");
						chanalert(s_opsb, "Warning, Couldnt get the address for %s. rr_info failed", scandata->who); 
						list_delete(opsbl, scannode);
						lnode_destroy(scannode);
						free(scandata);
						checkqueue();
					}
					free(show);
					break;
			case DO_OPM_LOOKUP:
					if (a->nrrs > 0) {
						/* TODO: print out what type of open proxy it is based on IP address returned */
						nlog(LOG_NOTICE, LOG_MOD, "Got Positive OPM lookup for %s (%s)", scandata->who, scandata->lookup);
						scandata->dnsstate = OPMLIST;
						opsb.opmhits++;
						chanalert(s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
						globops(s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
						if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
						sakill_cmd(inet_ntoa(scandata->ipaddr), "*", s_opsb, opsb.bantime, "Your host is listed as an Open Proxy. Please visit the following website for more info: www.blitzed.org/proxy?ip=%s", inet_ntoa(scandata->ipaddr));
						checkqueue();
					} else {
						if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "%s does not appear in DNS black list", scandata->lookup);
						nlog(LOG_DEBUG1, LOG_MOD, "Got Negative OPM lookup for %s (%s)", scandata->who, scandata->lookup);
						scandata->dnsstate = NOOPMLIST;
					}
					check_scan_free(scandata);
					break;
			default:
					nlog(LOG_WARNING, LOG_MOD, "Warning, Unknown Status in dnsblscan()");
			        	list_delete(opsbl, scannode);
			        	lnode_destroy(scannode);
			        	free(scandata);
					return;
		}
		return;
			
	} else {
		nlog(LOG_CRITICAL, LOG_MOD, "OPSP() Answer is Empty!");
        	list_delete(opsbl, scannode);
        	lnode_destroy(scannode);
        	free(scandata);
        }
                                                                                                                                                checkqueue();
	
}

/* this function is to send the results to the user after a lookup command */

void reportdns(char *data, adns_answer *a) {
	lnode_t *dnslookup;
	scaninfo *dnsinfo;
	char *show;
	int i, len, ri;

	SET_SEGV_LOCATION();
					
	dnslookup = list_find(opsbl, data, findscan);
	if (!dnslookup) {
		nlog(LOG_CRITICAL, LOG_MOD, "reportdns(): Ehhh, something wrong here %s", data);
		return;
	}
	dnsinfo = lnode_get(dnslookup);
	if (a) {
		adns_rr_info(a->type, 0, 0, &len, 0, 0);
		for(i = 0; i < a->nrrs;  i++) {
			ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes +i*len, &show);
			if (!ri) {
				prefmsg(data, s_opsb, "%s resolves to %s", dnsinfo->lookup, show);
			} else {
				prefmsg(data, s_opsb, "DNS error %s", adns_strerror(ri));
			}
			free(show);
		}
		if (a->nrrs < 1) {
			prefmsg(data, s_opsb, "%s Does not resolve", dnsinfo->lookup);
		}
	} else {
		prefmsg(data, s_opsb, "An unknown error occured");
	}	
	
	list_delete(opsbl, dnslookup);
	lnode_destroy(dnslookup);
	free(dnsinfo);
	checkqueue();
}

void LoadConfig(void)
{
	int i;
	lnode_t *node;
	char **data;
	char *tmp;
	char datapath[512];
	exemptinfo *exempts;

	if (GetConf((void *)&tmp, CFGSTR, "OpmDomain") <= 0) {
		strlcpy(opsb.opmdomain, "opm.blitzed.org", MAXHOST);
	} else {
		strlcpy(opsb.opmdomain, tmp, MAXHOST);
		free(tmp);
	}
	if (GetConf((void *)&tmp, CFGSTR, "TargetHost") <= 0) {
		strlcpy(opsb.targethost, me.uplink, MAXHOST);
	} else {
		strlcpy(opsb.targethost, tmp, MAXHOST);
		free(tmp);
	}
	if (GetConf((void *)&opsb.targetport, CFGINT, "TargetPort") <= 0) {
		opsb.targetport = me.port;
	}
	if (GetConf((void *)&opsb.maxbytes, CFGINT, "MaxBytes") <= 0) {
		opsb.maxbytes = 500;
	}
	if (GetConf((void *)&opsb.timeout, CFGINT, "TimeOut") <= 0) {
		opsb.timeout = 30;
	}
	if (GetConf((void *)&opsb.timedif, CFGINT, "SplitTime") <= 0) {
		opsb.timedif = 600;
	}
	if (GetConf((void *)&opsb.cachetime, CFGINT, "CacheTime") <= 0) {
		opsb.cachetime = 3600;
	}
	if (GetConf((void *)&opsb.bantime, CFGINT, "BanTime") <= 0) {
		opsb.bantime = 86400;
	}
	if (GetConf((void *)&opsb.doscan, CFGINT, "DoScan") <= 0) {
		opsb.doscan = 1;
	}
	if (GetConf((void *)&opsb.doban, CFGINT, "DoBan") <= 0) {
		opsb.doban = 1;
	}
	if (GetConf((void *)&opsb.confed, CFGINT, "Confed") <= 0) {
		opsb.confed = 0;
	}

	if (GetConf((void *)&tmp, CFGSTR, "TriggerString") <= 0) {
		strlcpy(opsb.lookforstring, "*** Looking up your hostname...", 512);
	} else {
		strlcpy(opsb.lookforstring, tmp, 512);
		free(tmp);
	}
	if (GetConf((void *)&tmp, CFGSTR, "ScanMsg") <= 0) {
		strlcpy(opsb.scanmsg, "Your Host is being Scanned for Open Proxies", 512);
	} else {
		strlcpy(opsb.scanmsg, tmp, 512);
		free(tmp);
	}
	
	if (GetDir("Exempt", &data) > 0) {
		/* try */
		for (i = 0; data[i] != NULL; i++) {
			exempts = malloc(sizeof(exemptinfo));
			strlcpy(exempts->host, data[i], MAXHOST);
	
			ircsnprintf(datapath, CONFBUFSIZE, "Exempt/%s/Who", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(exempts);
				continue;
			} else {
				strlcpy(exempts->who, tmp, MAXNICK);
				free(tmp);
			}
			ircsnprintf(datapath, CONFBUFSIZE, "Exempt/%s/Reason", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(exempts);
				continue;
			} else {
				strlcpy(exempts->reason, tmp, MAXREASON);
				free(tmp);
			}
			ircsnprintf(datapath, CONFBUFSIZE, "Exempt/%s/Server", data[i]);
			if (GetConf((void *)&exempts->server, CFGINT, datapath) <= 0) {
				free(exempts);
				continue;
			}			
			nlog(LOG_DEBUG2, LOG_MOD, "Adding %s (%d) Set by %s for %s to Exempt List", exempts->host, exempts->server, exempts->who, exempts->reason);
			node = lnode_create(exempts);
			list_prepend(exempt, node);			


		}
	}
	free(data);	
}

int __ModInit(int modnum, int apiver)
{
	strlcpy(s_opsb, "opsb", MAXNICK);

	/* we have to be careful here. Currently, we have 7 sockets that get opened per connection. Soooo.
	*  we check that MAX_SCANS is not greater than the maxsockets available / 7
	*  this way, we *shouldn't* get problems with running out of sockets 
	*/
	if (MAX_SCANS > me.maxsocks / 7) {
		opsbl = list_create(me.maxsocks /7);
		opsb.socks = me.maxsocks /7;
	} else {
		opsbl = list_create(MAX_SCANS);
		opsb.socks = MAX_SCANS;
	}
	/* queue can be anything we want */
	opsbq = list_create(MAX_QUEUE);


	/* scan cache is MAX_QUEUE size (why not?) */
	cache = list_create(MAX_QUEUE);

	exempt = list_create(MAX_EXEMPTS);

	opsb.ports = list_create(MAX_PORTS);

	LoadConfig();


	online = 0;				

	opsb.open = 0;
	opsb.scanned = 0;
	opsb.cachehits = 1;
	opsb.opmhits = 1;

	if (load_ports() != 1) {
		nlog(LOG_WARNING, LOG_MOD, "Can't Load opsb. No Ports Defined for Scanner. Did you install Correctly?");
		return -1;
	}
	init_libopm();


	return 1;
}


void __ModFini()
{
};


void save_exempts(exemptinfo *exempts) {
	char path[255];

	nlog(LOG_DEBUG1, LOG_MOD, "Saving Exempt List %s", exempts->host);
	ircsnprintf(path, 255, "Exempt/%s/Who", exempts->host);
	SetConf((void *)exempts->who, CFGSTR, path);
	ircsnprintf(path, 255, "Exempt/%s/Reason", exempts->host);
	SetConf((void *)exempts->reason, CFGSTR, path);
	ircsnprintf(path, 255, "Exempt/%s/Server", exempts->host);
	SetConf((void *)exempts->server, CFGINT, path);
}
