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

#include <stdio.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#endif
#include "neostats.h"
#include "opsb.h"
#include "exempts.h"

void reportdns(char *data, adns_answer *a);
void dnsblscan(char *data, adns_answer *a);
static int ScanNick (CmdParams* cmdparams);
int startscan(scaninfo *scandata);
void save_ports();
static int unconf(void);

Bot *opsb_bot;

/** Copyright info */
const char *opsb_copyright[] = {
	"Copyright (c) 1999-2004, NeoStats",
	"http://www.neostats.net/",
	NULL
};

/** Module Info definition 
 * version information about our module
 * This structure is required for your module to load and run on NeoStats
 */
ModuleInfo module_info = {
	"OPSB",
	"An Open Proxy Scanning Bot",
	opsb_copyright,
	opsb_about,
	NEOSTATS_VERSION,
	MODULE_VERSION,
	__DATE__,
	__TIME__,
	0,
	0,
};

int findscan(const void *key1, const void *key2) {
        const scaninfo *chan1 = key1;
        return (ircstrcasecmp (chan1->who, key2));
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
	}
	return -1;
}

int opsb_cmd_lookup (CmdParams* cmdparams) 
{
	lnode_t *lnode;
	scaninfo *scandata;
	int lookuptype;

	scandata = malloc(sizeof(scaninfo));
	scandata->dnsstate = REPORT_DNS;
	strlcpy(scandata->who, cmdparams->source->name, MAXNICK);
	strlcpy(scandata->lookup, cmdparams->av[0], MAXHOST);
	/* if the lists are full, don't add it, and alert the user */
	if (list_isfull(opsbl)) {
		if (list_isfull(opsbq)) {
			irc_prefmsg (opsb_bot, cmdparams->source, "Too Busy. Try again Later");
			free(scandata);
			return NS_SUCCESS;
		}
		irc_prefmsg (opsb_bot, cmdparams->source, "OPSB list is full, queuing your request");
		lnode = lnode_create(scandata);
		list_append(opsbq, lnode);
	}
	if (inet_aton(scandata->lookup, NULL) > 0) {
		lookuptype = adns_r_ptr;
	} else {
		if (cmdparams->ac == 2) {
			if (!ircstrcasecmp (cmdparams->av[1], "txt"))
				lookuptype = adns_r_txt;
			else if (!ircstrcasecmp (cmdparams->av[1], "rp"))
				lookuptype = adns_r_rp;
			else if (!ircstrcasecmp (cmdparams->av[1], "ns"))
				lookuptype = adns_r_ns;
			else if (!ircstrcasecmp (cmdparams->av[1], "soa"))
				lookuptype = adns_r_soa;
			else 
				lookuptype = adns_r_a;
		} else {
			lookuptype = adns_r_a;
		}
	}
	if (dns_lookup(scandata->lookup, lookuptype, reportdns, scandata->who) != 1) {
		irc_prefmsg (opsb_bot, cmdparams->source, "DnsLookup Failed.");
		free(scandata);
		return NS_FAILURE;
	} 
	lnode = lnode_create(scandata);
	list_append(opsbl, lnode);
	return NS_SUCCESS;
}

int opsb_cmd_remove (CmdParams* cmdparams) 
{
	irc_rakill (opsb_bot, cmdparams->av[0], "*");
	irc_chanalert (opsb_bot, "%s attempted to remove an akill for *@%s", cmdparams->source->name, cmdparams->av[0]);
	return NS_SUCCESS;
}

int opsb_cmd_check (CmdParams* cmdparams) 
{
	Client *u2;
	scaninfo *scandata;

	if ((list_find(opsbl, cmdparams->av[0], findscan)) || (list_find(opsbq, cmdparams->av[0], findscan))) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Already Scanning (or in queue) %s. Not Scanning again", cmdparams->av[0]);
		return NS_SUCCESS;
	}
	scandata = malloc(sizeof(scaninfo));
	scandata->doneban = 0;
	scandata->reqclient = cmdparams->source;
	if ((u2 = find_user(cmdparams->av[0])) != NULL) {
		/* don't scan users from my server */
		if (IsMe(u2)) {
			irc_prefmsg (opsb_bot, cmdparams->source, "Error, Can not scan NeoStats Bots");
			free(scandata);
			return -1;
		}
		strlcpy(scandata->who, u2->name, MAXHOST);
		strlcpy(scandata->lookup, u2->user->hostname, MAXHOST);
		strlcpy(scandata->server, u2->uplink->name, MAXHOST);
		scandata->ip.s_addr = u2->ip.s_addr;
		if (scandata->ip.s_addr > 0) {
			scandata->dnsstate = DO_OPM_LOOKUP;
		} else {
			/* if its here, we don't have the IP address yet */
			irc_prefmsg (opsb_bot, cmdparams->source, "Error: We don't have a IP address for %s yet. Try again soon", u2->name);
			free(scandata);
			return -1;
		}
	} else {
		strlcpy(scandata->who, cmdparams->av[0], MAXHOST);
		strlcpy(scandata->lookup, cmdparams->av[0], MAXHOST);
		memset (scandata->server, 0, MAXHOST);
		/* is it a ip address or host */
		if (inet_aton(cmdparams->av[0], &scandata->ip) > 0) {
			scandata->dnsstate = DO_OPM_LOOKUP;
		} else {
			scandata->dnsstate = DO_DNS_HOST_LOOKUP;
			scandata->ip.s_addr = 0;
		}
	}
	irc_prefmsg (opsb_bot, cmdparams->source, "Checking %s for open Proxies", cmdparams->av[0]);
	if (!startscan(scandata)) 
		irc_prefmsg (opsb_bot, cmdparams->source, "Check Failed");
	return NS_SUCCESS;
}

int opsb_cmd_ports_list (CmdParams* cmdparams) 
{
	port_list *pl;
	int i;
	lnode_t *lnode;

	lnode = list_first(opsb.ports);
	i = 1;
	irc_prefmsg (opsb_bot, cmdparams->source, "Port List:");
	while (lnode) {
		pl = lnode_get(lnode);
		irc_prefmsg (opsb_bot, cmdparams->source, "%d) %s Port: %d", i, type_of_proxy(pl->type), pl->port);
		++i;
		lnode = list_next(opsb.ports, lnode);
	}
	irc_prefmsg (opsb_bot, cmdparams->source, "End of list.");
	irc_chanalert (opsb_bot, "%s requested Port List", cmdparams->source->name);
	return NS_SUCCESS;
}

int opsb_cmd_ports_add (CmdParams* cmdparams) 
{
	port_list *pl;
	lnode_t *lnode;

	if (cmdparams->ac < 3) {
		return NS_ERR_SYNTAX_ERROR;
	}
	if (list_isfull(opsb.ports)) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Error, Ports list is full");
		return NS_SUCCESS;
	}
	if (!atoi(cmdparams->av[2])) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Port field does not contain a vaild port");
		return NS_SUCCESS;
	}
	if (get_proxy_by_name(cmdparams->av[1]) < 1) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Unknown Proxy type %s", cmdparams->av[1]);
		return NS_SUCCESS;
	}
	/* check for duplicates */
	lnode = list_first(opsb.ports);
	while (lnode) {
		pl = lnode_get(lnode);
		if ((pl->type == get_proxy_by_name(cmdparams->av[1])) && (pl->port == atoi(cmdparams->av[2]))) {
			irc_prefmsg (opsb_bot, cmdparams->source, "Duplicate Entry for Protocol %s", cmdparams->av[1]);
			return NS_SUCCESS;
		}
		lnode = list_next(opsb.ports, lnode);
	}
	pl = malloc(sizeof(port_list));
	pl->type = get_proxy_by_name(cmdparams->av[1]);
	pl->port = atoi(cmdparams->av[2]);
		
	lnode = lnode_create(pl);
	list_append(opsb.ports, lnode);
	list_sort(opsb.ports, ports_sort);
	save_ports();
	add_port(pl->type, pl->port);
	irc_prefmsg (opsb_bot, cmdparams->source, "Added Port %d for Protocol %s to Ports list", pl->port, cmdparams->av[1]);
	irc_chanalert (opsb_bot, "%s added port %d for protocol %s to Ports list", cmdparams->source->name, pl->port, cmdparams->av[1]);
	return NS_SUCCESS;
}

int opsb_cmd_ports_del (CmdParams* cmdparams) 
{
	port_list *pl;
	int i;
	lnode_t *lnode;

	if (cmdparams->ac < 1) {
		return NS_ERR_SYNTAX_ERROR;
	}
	if (atoi(cmdparams->av[1]) != 0) {
		lnode = list_first(opsb.ports);
		i = 1;
		while (lnode) {
			if (i == atoi(cmdparams->av[1])) {
				/* delete the entry */
				pl = lnode_get(lnode);
				list_delete(opsb.ports, lnode);
				irc_prefmsg (opsb_bot, cmdparams->source, "Deleted Port %d of Protocol %s out of Ports list", pl->port, type_of_proxy(pl->type));
				irc_prefmsg (opsb_bot, cmdparams->source, "You need to Restart OPSB for the changes to take effect");
				irc_chanalert (opsb_bot, "%s deleted port %d of Protocol %s out of Ports list", cmdparams->source->name, pl->port, type_of_proxy(pl->type));
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
		irc_prefmsg (opsb_bot, cmdparams->source, "Error, Can't find entry %d. /msg %s ports list", atoi(cmdparams->av[1]), opsb_bot->name);
	} else {
		irc_prefmsg (opsb_bot, cmdparams->source, "Error, Out of Range");
	}
	return NS_SUCCESS;
}

int opsb_cmd_ports (CmdParams* cmdparams) 
{
	if (!ircstrcasecmp (cmdparams->av[0], "LIST")) {
		return opsb_cmd_ports_list (cmdparams);
	} else if (!ircstrcasecmp (cmdparams->av[0], "ADD")) {
		return opsb_cmd_ports_add (cmdparams);
	} else if (!ircstrcasecmp (cmdparams->av[0], "DEL")) {
		return opsb_cmd_ports_del (cmdparams);
	}
	return NS_ERR_SYNTAX_ERROR;
}

int do_set_cb (CmdParams* cmdparams, SET_REASON reason)
{
	SetConf((void *)1, CFGINT, "Confed");
	del_timer("unconf");
	return NS_SUCCESS;
}

static bot_cmd opsb_commands[]=
{
	{"STATUS",	opsb_cmd_status,	0,	NS_ULEVEL_OPER,	opsb_help_status,	opsb_help_status_oneline},
	{"LOOKUP",	opsb_cmd_lookup,	1,	NS_ULEVEL_OPER,	opsb_help_lookup,	opsb_help_lookup_oneline},
	{"REMOVE",	opsb_cmd_remove,	1,	NS_ULEVEL_OPER,	opsb_help_remove,	opsb_help_remove_oneline},
	{"CHECK",	opsb_cmd_check,		1,	NS_ULEVEL_OPER,	opsb_help_check,	opsb_help_check_oneline},
	{"EXCLUDE",	opsb_cmd_exclude,	1,	NS_ULEVEL_ADMIN,opsb_help_exclude,	opsb_help_exclude_oneline},
	{"PORTS",	opsb_cmd_ports,		1,	NS_ULEVEL_ADMIN,opsb_help_ports,	opsb_help_ports_oneline},
	{NULL,		NULL,				0, 	0,				NULL, 				NULL}
};

static bot_setting opsb_settings[]=
{
	{"DISABLESCAN", &opsb.doscan,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN, "DoScan",		NULL,	opsb_help_set_disablescan,	do_set_cb, (void*)1 },
	{"DOBAN",		&opsb.doban,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN, "DoBan",		NULL,	opsb_help_set_doban,		do_set_cb, (void*)1 },
	{"TARGETIP",	&opsb.targethost,	SET_TYPE_IPV4,		0,	MAXHOST,	NS_ULEVEL_ADMIN, "TargetHost",	NULL,	opsb_help_set_targetip,		do_set_cb },
	{"TARGETPORT",	&opsb.targetport,	SET_TYPE_INT,		0,	65430,			NS_ULEVEL_ADMIN, "TargetPort",	NULL,	opsb_help_set_targetport,	do_set_cb },
	{"OPMDOMAIN",	&opsb.opmdomain,	SET_TYPE_HOST,		0,	MAXHOST,	NS_ULEVEL_ADMIN, "OpmDomain",	NULL,	opsb_help_set_opmdomain,	do_set_cb, (void*)"opm.blitzed.org" },
	{"MAXBYTES",	&opsb.maxbytes,		SET_TYPE_INT,		0,	100000,			NS_ULEVEL_ADMIN, "MaxBytes",	NULL,	opsb_help_set_maxbytes,		do_set_cb, (void*)500 },
	{"TIMEOUT",		&opsb.timeout,		SET_TYPE_INT,		0,	120,		NS_ULEVEL_ADMIN, "TimeOut",		NULL,	opsb_help_set_timeout,		do_set_cb, (void*)30 },
	{"OPENSTRING",	&opsb.lookforstring,SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN, "TriggerString",NULL,	opsb_help_set_openstring,	do_set_cb, (void*)"*** Looking up your hostname..." },
	{"SPLITTIME",	&opsb.timedif,		SET_TYPE_INT,		0,	900,			NS_ULEVEL_ADMIN, "SplitTime",	NULL,	opsb_help_set_splittime,	do_set_cb, (void*)600 },
	{"SCANMSG",		&opsb.scanmsg,		SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN, "ScanMsg",		NULL,	opsb_help_set_scanmsg,		do_set_cb, (void*)"Your Host is being Scanned for Open Proxies" },
	{"BANTIME",		&opsb.bantime,		SET_TYPE_INT,		0,	360000,			NS_ULEVEL_ADMIN, "BanTime",		NULL,	opsb_help_set_bantime,		do_set_cb, (void*)86400 },
	{"CACHETIME",	&opsb.cachetime,	SET_TYPE_INT,		0,	86400,			NS_ULEVEL_ADMIN, "CacheTime",	NULL,	opsb_help_set_cachetime,	do_set_cb, (void*)3600 },
	{"VERBOSE",		&opsb.verbose,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN, "Verbose",		NULL,	opsb_help_set_verbose,		do_set_cb, (void*)1 },
	{NULL,			NULL,				0,					0,	0, 			0,				 NULL,			NULL,	NULL,						NULL	},
};

/** BotInfo */
static BotInfo opsb_botinfo = 
{
	"opsb", 
	"opsb1", 
	"opsb", 
	BOT_COMMON_HOST, 
	"Proxy Scanning Bot", 	
	BOT_FLAG_SERVICEBOT|BOT_FLAG_RESTRICT_OPERS|BOT_FLAG_DEAF, 
	opsb_commands, 
	opsb_settings,
};

/** @brief ModSynch
 *
 *  Startup handler
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ModSynch (void)
{
	SET_SEGV_LOCATION();
	opsb_bot = AddBot (&opsb_botinfo);
	if (opsb.confed == 0) {
		add_timer (TIMER_TYPE_INTERVAL, unconf, "unconf", 60);
		unconf();
		strlcpy(opsb.targethost, me.uplink, MAXHOST);
	}
	if(opsb.verbose) {
		if (opsb.doscan) {
			irc_chanalert (opsb_bot, "Open Proxy Scanning bot has started (Concurrent Scans: %d Sockets %d)", opsb.socks, opsb.socks *7);
		} else {
			irc_chanalert (opsb_bot, "DNS Blacklist Lookup is only Enabled!! (No Open Proxy Scans)");
		}
	}
	return NS_SUCCESS;
};

static int unconf(void) 
{
	if (opsb.confed != 1) 
	{
		irc_chanalert (opsb_bot, "Warning, OPSB is configured with default Settings. Please Update this ASAP");
		irc_globops  (opsb_bot, "Warning, OPSB is configured with default Settings, Please Update this ASAP");
	}
	return NS_SUCCESS;
}

void save_ports() 
{
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

void checkqueue() 
{
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

void addtocache(unsigned long ip) 
{
	lnode_t *cachenode;
	cache_entry *ce;

	SET_SEGV_LOCATION();
			
	/* pop off the oldest entry */
	if (list_isfull(cache)) {
		dlog (DEBUG2, "OPSB: Deleting Tail of Cache: %d", (int)list_count(cache));
		cachenode = list_del_last(cache);
		ce = lnode_get(cachenode);
		lnode_destroy(cachenode);
		free(ce);
	}
	cachenode = list_first(cache);
	while (cachenode) {
		ce = lnode_get(cachenode);
		if (ce->ip == ip) {
			dlog (DEBUG2,"OPSB: Not adding %ld to cache as it already exists", ip);
			return;
		}
		cachenode = list_next(cache, cachenode);
	}
	
	ce = malloc(sizeof(cache_entry));
	ce->ip = ip;
	ce->when = time(NULL);
	cachenode = lnode_create(ce);
	list_prepend(cache, cachenode);
}

int checkcache(scaninfo *scandata) 
{
	lnode_t *node, *node2;
	cache_entry *ce;

	SET_SEGV_LOCATION();
	if (scandata->server && IsServerExempt (scandata->who, scandata->server))
		return 1;
	if (IsUserExempt (scandata->who, scandata->lookup))
		return 2;
	node = list_first(cache);
	while (node) {
		ce = lnode_get(node);
		
		/* delete any old cache entries */
	
		if ((time(NULL) - ce->when) > opsb.cachetime) {
			dlog (DEBUG1, "OPSB: Deleting old cache entry %ld", ce->ip);
			node2 = list_next(cache, node);			
			list_delete(cache, node);
			lnode_destroy(node);
			free(ce);
			node = node2;
			break;
		}
		if (ce->ip == scandata->ip.s_addr) {
			dlog (DEBUG1, "OPSB: user %s is already in Cache", scandata->who);
			opsb.cachehits++;
			if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "User %s is already in Cache", scandata->who);
			return 3;
		}
		node = list_next(cache, node);
	}
	return 0;
}

ModuleEvent module_events[] = 
{
	{ EVENT_NICKIP, 	ScanNick, EVENT_FLAG_EXCLUDE_ME},
	{ EVENT_NULL, 	NULL}
};

/* this function kicks of a scan of a user that just signed on the network */
static int ScanNick (CmdParams* cmdparams)
{
	scaninfo *scandata;
	lnode_t *scannode;

	SET_SEGV_LOCATION();

	/* don't scan users from a server that is excluded */
	if (IsServerExempt (cmdparams->source->name, cmdparams->source->uplink->name))
	{
		return -1;
	}
	if (time(NULL) - cmdparams->source->tsconnect > opsb.timedif) {
		dlog (DEBUG1, "Netsplit Nick %s, Not Scanning", cmdparams->source->name);
		return -1;
	}
	scannode = list_find(opsbl, cmdparams->source->name, findscan);
	if (!scannode) scannode = list_find(opsbq, cmdparams->source->name, findscan);
	if (scannode) {
		dlog (DEBUG1, "ScanNick(): Not scanning %s as we are already scanning them", cmdparams->source->name);
		return -1;
	}
	irc_prefmsg (opsb_bot, cmdparams->source, "%s", opsb.scanmsg);
	scandata = malloc(sizeof(scaninfo));
	scandata->reqclient = NULL;
	scandata->doneban = 0;
	strlcpy(scandata->who, cmdparams->source->name, MAXHOST);
	strlcpy(scandata->lookup, cmdparams->source->user->hostname, MAXHOST);
	strlcpy(scandata->server, cmdparams->source->uplink->name, MAXHOST);
	/*strlcpy(scandata->connectstring, recbuf, BUFSIZE);*/
	scandata->ip.s_addr = cmdparams->source->ip.s_addr;
	scandata->dnsstate = DO_OPM_LOOKUP;
	if (!startscan(scandata)) {
		irc_chanalert (opsb_bot, "Warning Can't scan %s", cmdparams->source->name);
		nlog (LOG_WARNING, "OBSB ScanNick(): Can't scan %s. Check logs for possible errors", cmdparams->source->name);
	}
	return 1;
}

/* this function is the entry point for all scans. Any scan you want to kick off is started with this function. */
/* this includes moving scans from the queue to the active list */

int startscan(scaninfo *scandata) 
{
	lnode_t *scannode;
	unsigned char a, b, c, d;
	char *buf;
	int buflen;
	int i;

	SET_SEGV_LOCATION();
	
	/* only check the cache when we have IP addy */
	if (scandata->dnsstate == DO_OPM_LOOKUP) {
		i = checkcache(scandata);
		if ((i > 0) && (scandata->reqclient == NULL)) {
			free(scandata);
			return 1;
		}
	}
	switch(scandata->dnsstate) {
		case DO_DNS_HOST_LOOKUP:
				if (list_isfull(opsbl)) {
					if (list_isfull(opsbq)) {
						irc_chanalert (opsb_bot, "Warning, Both Current and queue lists are full. Not Adding additional scans");
						dlog (DEBUG1, "OPSB: dropped scaning of %s, as queue is full", scandata->who);
						if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "To Busy. Try again later");
						free(scandata);
						return 0;
					}
					scannode = lnode_create(scandata);
					list_append(opsbq, scannode);
					dlog (DEBUG1, "DNS: Added %s to dns queue", scandata->who);
					if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Your Request has been added to the Queue");
					return 1;
				}
				if (dns_lookup(scandata->lookup, adns_r_a, dnsblscan, scandata->who) != 1) {
					nlog (LOG_WARNING, "DNS: startscan() DO_DNS_HOST_LOOKUP dns_lookup() failed");
					free(scandata);
					checkqueue();
					return 0;
				}

				scannode = lnode_create(scandata);
				list_append(opsbl, scannode);
				dlog (DEBUG1, "DNS: Added getnickip to DNS active list");
				return 1;		
				break;
		case DO_OPM_LOOKUP:
				if (list_isfull(opsbl)) {
					if(list_isfull(opsbq)) {
						irc_chanalert (opsb_bot, "Warning, Both Current and Queue lists are full, Not adding Scan");
						if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Too Busy. Try again Later");
						free(scandata);
						return 0;
					}
					scannode = lnode_create(scandata);
					list_append(opsbq, scannode);
					dlog (DEBUG1, "DNS: Added OPM lookup to queue: %s", scandata->who);
					return 1;
				}
        		d = (unsigned char) (scandata->ip.s_addr >> 24) & 0xFF;
                c = (unsigned char) (scandata->ip.s_addr >> 16) & 0xFF;
                b = (unsigned char) (scandata->ip.s_addr >> 8) & 0xFF;
                a = (unsigned char) scandata->ip.s_addr & 0xFF;
                                
                /* Enough for a reversed IP and the zone. */
                buflen = 18 + strlen(opsb.opmdomain);
                buf = malloc(buflen * sizeof(*buf));
                                                     
                ircsnprintf(buf, buflen, "%d.%d.%d.%d.%s", d, c, b, a, opsb.opmdomain);
				if (dns_lookup(buf, adns_r_a, dnsblscan, scandata->who) != 1) {
					nlog (LOG_WARNING, "DNS: startscan() DO_OPM_LOOKUP dns_lookup() failed");
					free(scandata);
					free(buf);
					checkqueue();
					return 0;
				}
				scannode = lnode_create(scandata);
				list_append(opsbl, scannode);
				dlog (DEBUG1, "DNS: Added OPM %s lookup to DNS active list", buf);
				free(buf);
				start_proxy_scan(lnode_get(scannode));
				++opsb.scanned;
				return 1;
				break;
		default:
				nlog (LOG_WARNING, "Warning, Unknown Status in startscan()");
				free(scandata);
				return -1;
	}
}

/* this function is called when either checking the opm list, or when we are trying to resolve the hostname */

void dnsblscan(char *data, adns_answer *a) 
{
	lnode_t *scannode;
	scaninfo *scandata;
	char *show;
	int len, ri;

	SET_SEGV_LOCATION();

	scannode = list_find(opsbl, data, findscan);
	if (!scannode) {
		nlog (LOG_CRITICAL, "dnsblscan(): Ehhh, Something is wrong here - Can't find %s", data);
		return;
	}
	scandata = lnode_get(scannode);
	if (a) {
		switch(scandata->dnsstate) {
			case DO_DNS_HOST_LOOKUP:
					if (a->nrrs < 1) {
						irc_chanalert (opsb_bot, "No Record for %s. Aborting Scan", scandata->lookup);
						if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "No A record for %s. Aborting Scan", scandata->lookup);
						list_delete(opsbl, scannode);
						lnode_destroy(scannode);
						free(scandata);
						checkqueue();
						break;
					}
					adns_rr_info(a->type, 0, 0, &len, 0, 0);
					ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes, &show);
					if (!ri) {
						dlog (DEBUG1, "DNS: Got IP for %s -> %s", scandata->who, show);
						if (a->nrrs > 1) {
							irc_chanalert (opsb_bot, "Warning, More than one IP address for %s. Using %s only", scandata->lookup, show);
							if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Warning, More than one IP address for %s. Using %s only", scandata->lookup, show);
						}
						if (inet_aton(show, &scandata->ip) > 0) {
							scandata->dnsstate = DO_OPM_LOOKUP;
							list_delete(opsbl, scannode);
							lnode_destroy(scannode);
							startscan(scandata);
						} else {
							nlog (LOG_CRITICAL, "DNS: dnsblscan() GETNICKIP failed-> %s", show);
							irc_chanalert (opsb_bot, "Warning, Couldn't get the address for %s", scandata->who);
					        	list_delete(opsbl, scannode);
			        			lnode_destroy(scannode);
			        			free(scandata);
							checkqueue();
						}

					} else {
						nlog (LOG_CRITICAL, "DNS: dnsblscan GETNICKIP rr_info failed");
						irc_chanalert (opsb_bot, "Warning, Couldnt get the address for %s. rr_info failed", scandata->who); 
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
						nlog (LOG_NOTICE, "Got Positive OPM lookup for %s (%s)", scandata->who, scandata->lookup);
						scandata->dnsstate = OPMLIST;
						opsb.opmhits++;
						irc_chanalert (opsb_bot, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ip), opsb.opmdomain);
						irc_globops  (opsb_bot, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ip), opsb.opmdomain);
						if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ip), opsb.opmdomain);
						irc_akill (opsb_bot, inet_ntoa(scandata->ip), "*", opsb.bantime, "Your host is listed as an Open Proxy. Please visit the following website for more info: www.blitzed.org/proxy?ip=%s", inet_ntoa(scandata->ip));
						checkqueue();
					} else {
						if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "%s does not appear in DNS black list", scandata->lookup);
						dlog (DEBUG1, "Got Negative OPM lookup for %s (%s)", scandata->who, scandata->lookup);
						scandata->dnsstate = NOOPMLIST;
					}
					check_scan_free(scandata);
					break;
			default:
					nlog (LOG_WARNING, "Warning, Unknown Status in dnsblscan()");
			        	list_delete(opsbl, scannode);
			        	lnode_destroy(scannode);
			        	free(scandata);
					return;
		}
		return;			
	} else {
		nlog (LOG_CRITICAL, "OPSP() Answer is Empty!");
        	list_delete(opsbl, scannode);
        	lnode_destroy(scannode);
        	free(scandata);
	}
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
		nlog (LOG_CRITICAL, "reportdns(): Ehhh, something wrong here %s", data);
		return;
	}
	dnsinfo = lnode_get(dnslookup);
	if (a) {
		adns_rr_info(a->type, 0, 0, &len, 0, 0);
		for(i = 0; i < a->nrrs;  i++) {
			ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes +i*len, &show);
			if (!ri) {
				irc_prefmsg (opsb_bot, find_user (data), "%s resolves to %s", dnsinfo->lookup, show);
			} else {
				irc_prefmsg (opsb_bot, find_user (data), "DNS error %s", adns_strerror(ri));
			}
			free(show);
		}
		if (a->nrrs < 1) {
			irc_prefmsg (opsb_bot, find_user (data), "%s Does not resolve", dnsinfo->lookup);
		}
	} else {
		irc_prefmsg (opsb_bot, find_user (data), "An unknown error occured");
	}	
	
	list_delete(opsbl, dnslookup);
	lnode_destroy(dnslookup);
	free(dnsinfo);
	checkqueue();
}

int ModInit (Module *mod_ptr)
{
	strlcpy(opsb.targethost, me.uplink, MAXHOST);
	opsb.targetport = me.port;
	opsb.confed = 0;
	ModuleConfig (opsb_settings);
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
	opsb.ports = list_create(MAX_PORTS);
	LoadExempts();
	opsb.open = 0;
	opsb.scanned = 0;
	opsb.cachehits = 1;
	opsb.opmhits = 1;
	if (load_ports() != 1) {
		nlog (LOG_WARNING, "Can't Load opsb. No Ports Defined for Scanner. Did you install Correctly?");
		return NS_FAILURE;
	}
	init_libopm();
	/* tell NeoStats we want nickip */
	me.want_nickip = 1;
	return NS_SUCCESS;
}

void ModFini()
{
}
