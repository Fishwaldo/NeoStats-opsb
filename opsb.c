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

/*  TODO:
 *  - Akill support.
 *  - remove akill must check whether an akill was added by opsb before 
 *    removing it otherwise blsb becomes a way for opers to remove any 
 *    akill on the network including those they may not normally have 
 *    access to.
 */

#include "neostats.h"
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include "opsb.h"

typedef struct cache_entry {
	unsigned long ip;
	time_t when;
} cache_entry;

static void dns_callback( void *scandata, adns_answer *a );
static int startscan( scaninfo *scandata );
static int unconf( void* );
static int event_nickip (const CmdParams *cmdparams);
static int opsb_cmd_list( const CmdParams *cmdparams );
static int opsb_cmd_add( const CmdParams *cmdparams );
static int opsb_cmd_del( const CmdParams *cmdparams );
static int opsb_cmd_check( const CmdParams *cmdparams );
static int opsb_cmd_remove( const CmdParams *cmdparams );
static int opsb_set_cb( const CmdParams *cmdparams, SET_REASON reason );
static int opsb_set_target_cb( const CmdParams *cmdparams, SET_REASON reason );
static int opsb_set_exclusions_cb( const CmdParams *cmdparams, SET_REASON reason );

Bot *opsb_bot;
opsbcfg opsb;
list_t *opsbq;
list_t *opsbl;
list_t *cache;

/** Copyright info */
static const char *opsb_copyright[] = {
	"Copyright (c) 1999-2005, NeoStats",
	"http://www.neostats.net/",
	NULL
};

/** Module Info definition 
 * version information about our module
 * This structure is required for your module to load and run on NeoStats
 */
ModuleInfo module_info = {
	"OPSB",
	"Open Proxy Scanning Bot",
	opsb_copyright,
	opsb_about,
	NEOSTATS_VERSION,
	MODULE_VERSION,
	__DATE__,
	__TIME__,
	MODULE_FLAG_LOCAL_EXCLUDES,
	0,
	0,
};

static bot_cmd opsb_commands[]=
{
	{"STATUS",	opsb_cmd_status,	0,	NS_ULEVEL_OPER,		opsb_help_status, 0, NULL, NULL},
	{"REMOVE",	opsb_cmd_remove,	1,	NS_ULEVEL_OPER,		opsb_help_remove, 0, NULL, NULL},
	{"CHECK",	opsb_cmd_check,		1,	NS_ULEVEL_OPER,		opsb_help_check, 0, NULL, NULL},
	{"ADD",		opsb_cmd_add,		2,	NS_ULEVEL_ADMIN,	opsb_help_add, 0, NULL, NULL},
	{"DEL",		opsb_cmd_del,		1,	NS_ULEVEL_ADMIN,	opsb_help_del, 0, NULL, NULL},
	{"LIST",	opsb_cmd_list,		0,	NS_ULEVEL_ADMIN,	opsb_help_list, 0, NULL, NULL},
	NS_CMD_END()
};

static bot_setting opsb_settings[]=
{
	{"TARGETIP",	opsb.targetip,		SET_TYPE_IPV4,	0,	MAXHOST,NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_targetip,	opsb_set_target_cb, (void*)0 		},
	{"TARGETPORT",	&opsb.targetport,	SET_TYPE_INT,	0,	65535,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_targetport,	opsb_set_target_cb, (void*)6667	},
	{"AKILL",		&opsb.doakill,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_akill,	opsb_set_cb, (void*)1 	},	
	{"AKILLTIME",	&opsb.akilltime,	SET_TYPE_INT,	0,	20736000,NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_akilltime,	opsb_set_cb, (void*)TS_ONE_DAY 	},
	{"MAXBYTES",	&opsb.maxbytes,		SET_TYPE_INT,	0,	100000,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_maxbytes,	opsb_set_cb, (void*)500 	},
	{"TIMEOUT",		&opsb.timeout,		SET_TYPE_INT,	0,	120,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_timeout,	opsb_set_cb, (void*)30 	},
	{"OPENSTRING",	opsb.openstring,	SET_TYPE_MSG,	0,	BUFSIZE,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_openstring,	opsb_set_cb, (void*)"*** Looking up your hostname..." },
	{"SCANMSG",		opsb.scanmsg,		SET_TYPE_MSG,	0,	BUFSIZE,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_scanmsg,	opsb_set_cb, (void*)"Your Host is being Scanned for Open Proxies" },
	{"CACHETIME",	&opsb.cachetime,	SET_TYPE_INT,	0,	TS_ONE_DAY,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_cachetime,	opsb_set_cb, (void*)TS_ONE_HOUR 	},
	{"CACHESIZE",	&opsb.cachesize,	SET_TYPE_INT,	0,	10000,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_cachesize,	opsb_set_cb, (void*)1000	},
	{"VERBOSE",		&opsb.verbose,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN, 	NULL,	opsb_help_set_verbose,	opsb_set_cb, (void*)1 	},
	{"EXCLUSIONS",	&opsb.exclusions,	SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN,	NULL,	opsb_help_set_exclusions,	opsb_set_exclusions_cb, (void *)0 },
	{"DOREPORT",	&opsb.doreport, SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN,  NULL,	opsb_help_set_doreport,	opsb_set_cb, (void *)1},	
	NS_SETTING_END()
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

ModuleEvent module_events[] = 
{
	{ EVENT_NICKIP, event_nickip, EVENT_FLAG_EXCLUDE_ME },
	NS_EVENT_END()
};


/** @brief ports_sort
 *
 *  list handler to find scan
 *
 *  @param 
 *
 *  @return 
 */

int findscan( const void *key1, const void *key2 )
{
	const scaninfo *chan1 = key1;

	return ircstrcasecmp( chan1->who, key2 );
}

/** @brief ports_sort
 *
 *  Sort ports list handler
 *
 *  @param 
 *
 *  @return 
 */

static int ports_sort( const void *key1, const void *key2 )
{
	port_list *pl1 = (port_list *)key1;
	port_list *pl2 = (port_list *)key2;

	if (pl1->type == pl2->type)
	{
		if (pl1->port == pl2->port)
			return 0;
		if (pl1->port > pl2->port)
			return 1;
		return -1;
	}
	if (pl1->type > pl2->type)
		return 1;
	return -1;
}


/** @brief opsb_cmd_remove
 *
 *  REMOVE command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int opsb_cmd_remove( const CmdParams *cmdparams )
{
	irc_rakill (opsb_bot, cmdparams->av[0], "*");
	irc_chanalert (opsb_bot, "%s attempted to remove an akill for *@%s", cmdparams->source->name, cmdparams->av[0]);
	return NS_SUCCESS;
}

/** @brief opsb_cmd_check
 *
 *  CHECK command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int opsb_cmd_check( const CmdParams *cmdparams )
{
	Client *scanuser;
	scaninfo *scandata;

	if ((list_find(opsbl, cmdparams->av[0], findscan)) || (list_find(opsbq, cmdparams->av[0], findscan))) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Already Scanning (or in queue) %s. Not Scanning again", cmdparams->av[0]);
		return NS_SUCCESS;
	}
	scandata = ns_malloc( sizeof( scaninfo ) );
	scandata->doneban = 0;
	scandata->reqclient = cmdparams->source;
	scanuser = FindUser( cmdparams->av[0] );
	if( scanuser ) {
		/* don't scan users from my server */
		if (IsMe(scanuser)) {
			irc_prefmsg (opsb_bot, cmdparams->source, "Error, Can not scan NeoStats Bots");
			ns_free(scandata);
			return NS_SUCCESS;
		}
		if (scanuser->ip.s_addr == 0) {
			/* if its here, we don't have the IP address yet */
			irc_prefmsg (opsb_bot, cmdparams->source, "Error: We don't have a IP address for %s.", scanuser->name);
			ns_free(scandata);
			return NS_SUCCESS;
		}
		strlcpy(scandata->who, scanuser->name, MAXHOST);
		strlcpy(scandata->lookup, scanuser->user->hostname, MAXHOST);
		strlcpy(scandata->server, scanuser->uplink->name, MAXHOST);
		scandata->ip.s_addr = scanuser->ip.s_addr;
	} else {
		strlcpy(scandata->who, cmdparams->av[0], MAXHOST);
		strlcpy(scandata->lookup, cmdparams->av[0], MAXHOST);
		os_memset (scandata->server, 0, MAXHOST);
		/* is it a ip address or host */
		if (inet_aton(cmdparams->av[0], &scandata->ip) <= 0) {
			scandata->ip.s_addr = 0;
			if (dns_lookup(scandata->lookup, adns_r_a, dns_callback, (void *)scandata) != 1) {
				nlog (LOG_WARNING, "DNS: startscan() DO_DNS_HOST_LOOKUP dns_lookup() failed");
				ns_free(scandata);
				return NS_SUCCESS;
			}
			irc_prefmsg (opsb_bot, cmdparams->source, "Checking %s for open Proxies", cmdparams->av[0]);
			return NS_SUCCESS;
		}
	}
	irc_prefmsg (opsb_bot, cmdparams->source, "Checking %s for open Proxies", cmdparams->av[0]);
	if (!startscan(scandata)) 
		irc_prefmsg (opsb_bot, cmdparams->source, "Check Failed");
	return NS_SUCCESS;
}

/** @brief opsb_cmd_list
 *
 *  LIST command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int opsb_cmd_list (const CmdParams *cmdparams) 
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
	CommandReport(opsb_bot, "%s requested Port List", cmdparams->source->name);
	return NS_SUCCESS;
}

/** @brief opsb_cmd_add
 *
 *  ADD command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int opsb_cmd_add (const CmdParams *cmdparams) 
{
	port_list *pl;
	lnode_t *lnode;

	if (list_isfull(opsb.ports)) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Error, Ports list is full");
		return NS_SUCCESS;
	}
	if (!atoi(cmdparams->av[1])) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Port field does not contain a valid port");
		return NS_SUCCESS;
	}
	if (get_proxy_by_name(cmdparams->av[0]) < 1) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Unknown Proxy type %s", cmdparams->av[1]);
		return NS_SUCCESS;
	}
	/* check for duplicates */
	lnode = list_first(opsb.ports);
	while (lnode) {
		pl = lnode_get(lnode);
		if ((pl->type == get_proxy_by_name(cmdparams->av[0])) && (pl->port == atoi(cmdparams->av[1]))) {
			irc_prefmsg (opsb_bot, cmdparams->source, "Duplicate Entry for Protocol %s", cmdparams->av[0]);
			return NS_SUCCESS;
		}
		lnode = list_next(opsb.ports, lnode);
	}
	pl = ns_malloc(sizeof(port_list));
	pl->type = get_proxy_by_name(cmdparams->av[1]);
	pl->port = atoi(cmdparams->av[2]);
		
	lnode_create_append(opsb.ports, pl);
	list_sort(opsb.ports, ports_sort);
	save_ports();
/* 	add_port(pl->type, pl->port); */
	irc_prefmsg (opsb_bot, cmdparams->source, "Added Port %d for Protocol %s to Ports list", pl->port, cmdparams->av[0]);
	CommandReport(opsb_bot, "%s added port %d for protocol %s to Ports list", cmdparams->source->name, pl->port, cmdparams->av[0]);
	return NS_SUCCESS;
}

/** @brief opsb_cmd_del
 *
 *  DEL command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int opsb_cmd_del (const CmdParams *cmdparams) 
{
	port_list *pl;
	int i;
	lnode_t *lnode;

	if (atoi(cmdparams->av[0]) != 0) {
		lnode = list_first(opsb.ports);
		i = 1;
		while (lnode) {
			if (i == atoi(cmdparams->av[0])) {
				/* delete the entry */
				pl = lnode_get(lnode);
				list_delete(opsb.ports, lnode);
				lnode_destroy(lnode);
				irc_prefmsg (opsb_bot, cmdparams->source, "Deleted Port %d of Protocol %s out of Ports list", pl->port, type_of_proxy(pl->type));
				irc_prefmsg (opsb_bot, cmdparams->source, "You need to Restart OPSB for the changes to take effect");
				CommandReport(opsb_bot, "%s deleted port %d of Protocol %s out of Ports list", cmdparams->source->name, pl->port, type_of_proxy(pl->type));
				ns_free(pl);
				/* just to be sure, lets sort the list */
				list_sort(opsb.ports, ports_sort);
				save_ports();
				return 1;
			}
			++i;
			lnode = list_next(opsb.ports, lnode);
		}		
		/* if we get here, then we can't find the entry */
		irc_prefmsg (opsb_bot, cmdparams->source, "Error, Can't find entry %d. /msg %s ports list", atoi(cmdparams->av[0]), opsb_bot->name);
	} else {
		irc_prefmsg (opsb_bot, cmdparams->source, "Error, Out of Range");
	}
	return NS_SUCCESS;
}

/** @brief opsb_set_cb
 *
 *  Set callback
 *  Remove unconfigured warning if needed
 *
 *  @cmdparams pointer to commands param struct
 *  @cmdparams reason for SET
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int opsb_set_cb( const CmdParams *cmdparams, SET_REASON reason )
{
	if( reason == SET_CHANGE )
	{
		opsb.confed = 1;
		DBAStoreConfigInt ("Confed", &opsb.confed);
		DelTimer("unconf");
	}
	return NS_SUCCESS;
}

/** @brief opsb_set_cb
 *
 *  Set callback
 *  Remove unconfigured warning if needed
 *
 *  @cmdparams pointer to commands param struct
 *  @cmdparams reason for SET
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int opsb_set_target_cb( const CmdParams *cmdparams, SET_REASON reason )
{
	if( reason == SET_CHANGE )
	{
		(void)opsb_set_cb( cmdparams, reason );
		(void)init_scanengine();
	}
	return NS_SUCCESS;
}

/** @brief opsb_set_exclusions_cb
 *
 *  Set callback for exclusions
 *  Enable or disable exclude event flag
 *
 *  @cmdparams pointer to commands param struct
 *  @cmdparams reason for SET
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

static int opsb_set_exclusions_cb( const CmdParams *cmdparams, SET_REASON reason )
{
	if( reason == SET_LOAD || reason == SET_CHANGE )
	{
		SetAllEventFlags( EVENT_FLAG_USE_EXCLUDE, opsb.exclusions );
	}
	return NS_SUCCESS;
}

/** @brief unconf
 *
 *  unconfigured warn timer callback
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

static int unconf(void *userptr) 
{
	if (opsb.confed != 1) 
	{
		irc_chanalert (opsb_bot, "Warning, OPSB is configured with default Settings. Please Update this ASAP");
		irc_globops  (opsb_bot, "Warning, OPSB is configured with default Settings, Please Update this ASAP");
	}
	return NS_SUCCESS;
}

/** @brief checkqueue
 *
 *  check queue
 *
 *  @param none
 *
 *  @return none
 */

void checkqueue( void )
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
	(void)startscan(scandata);
}

/** @brief addtocache
 *
 *  add to cache
 *
 *  @param ip
 *
 *  @return 
 */

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
		ns_free(ce);
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
	
	ce = ns_malloc(sizeof(cache_entry));
	ce->ip = ip;
	ce->when = time(NULL);
	lnode_create_append(cache, ce);
}

/** @brief checkcache
 *
 *  check cache
 *
 *  @param scandata
 *
 *  @return 
 */

static int checkcache(scaninfo *scandata) 
{
	Client *scanclient;
	lnode_t *node, *node2;
	cache_entry *ce;

	SET_SEGV_LOCATION();
	if( scandata->server )
	{
		scanclient = FindServer(scandata->server);
		if( scanclient && ModIsServerExcluded( scanclient ) )
		{
			return 1;
		}
	}
	if( scandata->who )
	{
		scanclient = FindUser(scandata->who);
		if( scanclient && ModIsUserExcluded( scanclient ) )
		{
			return 2;
		}
	}
	node = list_first(cache);
	while (node) {
		ce = lnode_get(node);
		
		/* delete any old cache entries */
	
		if ((time(NULL) - ce->when) > opsb.cachetime) {
			dlog (DEBUG1, "OPSB: Deleting old cache entry %ld", ce->ip);
			node2 = list_next(cache, node);			
			list_delete(cache, node);
			lnode_destroy(node);
			ns_free(ce);
			node = node2;
			break;
		}
		if (ce->ip == scandata->ip.s_addr) {
			dlog (DEBUG1, "OPSB: user %s is already in Cache", scandata->who);
			opsb.cachehits++;
			if (scandata->reqclient) 
				irc_prefmsg (opsb_bot, scandata->reqclient, "User %s is already in Cache", scandata->who);
			return 3;
		}
		node = list_next(cache, node);
	}
	return 0;
}

/** @brief event_nickip
 *
 *  NICKIP event handler
 *  scan user that just signed on the network
 *
 *  @cmdparams pointer to commands param struct
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

static int event_nickip (const CmdParams *cmdparams)
{
	scaninfo *scandata;
	lnode_t *scannode;

	SET_SEGV_LOCATION();

	/* don't scan users from a server that is excluded */
	if( ModIsServerExcluded( cmdparams->source->uplink ) )
		return NS_SUCCESS;
	if( IsNetSplit( cmdparams->source ) )
	{
		dlog( DEBUG1, "Ignoring netsplit nick %s", cmdparams->source->name );
		return NS_SUCCESS;
	}
	scannode = list_find(opsbl, cmdparams->source->name, findscan);
	if (!scannode)
		scannode = list_find(opsbq, cmdparams->source->name, findscan);
	if (scannode)
	{
		dlog (DEBUG1, "event_nickip: Not scanning %s as we are already scanning them", cmdparams->source->name);
		return NS_SUCCESS;
	}
	irc_prefmsg (opsb_bot, cmdparams->source, "%s", opsb.scanmsg);
	scandata = ns_malloc(sizeof(scaninfo));
	scandata->reqclient = NULL;
	scandata->doneban = 0;
	strlcpy(scandata->who, cmdparams->source->name, MAXHOST);
	strlcpy(scandata->lookup, cmdparams->source->user->hostname, MAXHOST);
	strlcpy(scandata->server, cmdparams->source->uplink->name, MAXHOST);
	scandata->ip.s_addr = cmdparams->source->ip.s_addr;
	if (!startscan(scandata)) {
		irc_chanalert (opsb_bot, "Warning Can't scan %s", cmdparams->source->name);
		nlog (LOG_WARNING, "OBSB event_nickip: Can't scan %s. Check logs for possible errors", cmdparams->source->name);
	}
	return NS_SUCCESS;
}

/** @brief startscan
 *
 *  entry point for all scans including moving scans 
 *  from the queue to the active list
 *
 *  @param scaninfo *scandata
 *
 *  @return 
 */

static int startscan(scaninfo *scandata) 
{
	int i;

	SET_SEGV_LOCATION();
	
	/* only check the cache when we have IP addy */
	if (scandata->ip.s_addr > 0) {
		i = checkcache(scandata);
		if ((i > 0) && (scandata->reqclient == NULL)) {
			ns_free(scandata);
			return 1;
		}
	}
	if (list_isfull(opsbl)) {
		if (list_isfull(opsbq)) {
			irc_chanalert (opsb_bot, "Warning, Both Current and queue lists are full. Not Adding additional scans");
			dlog (DEBUG1, "OPSB: dropped scanning of %s, as queue is full", scandata->who);
			if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "To Busy. Try again later");
			ns_free(scandata);
			return 0;
		}
		lnode_create_append(opsbq, scandata);
		dlog (DEBUG1, "OPSB: Added %s to dns queue", scandata->who);
		if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Your Request has been added to the Queue");
		return 1;
	}
	start_proxy_scan(scandata);
#if 0	
	if (dns_lookup(scandata->lookup, adns_r_a, dns_callback, scandata) != 1) {
		nlog (LOG_WARNING, "OPSB: startscan() DO_DNS_HOST_LOOKUP dns_lookup() failed");
		ns_free(scandata);
		checkqueue();
		return 0;
	}
#endif
	lnode_create_append(opsbl, scandata);
	dlog (DEBUG1, "OPSB: Added %s to Scan active list", scandata->who);
	return 1;		
}

/** @brief dns_callback
 *
 *  DNS callback
 *
 *  @param data
 *  @param a
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

/* this function is called when either checking the opm list, or when we are trying to resolve the hostname */

static void dns_callback(void *data, adns_answer *a) 
{
	scaninfo *scandata = (scaninfo *)data;
	char *show;
	int len, ri;

	SET_SEGV_LOCATION();

	if (a) {
		if (a->nrrs < 1) {
			irc_chanalert (opsb_bot, "No Record for %s. Aborting Scan", scandata->lookup);
			if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "No A record for %s. Aborting Scan", scandata->lookup);
			ns_free(scandata);
			checkqueue();
			return;
		}
		adns_rr_info(a->type, 0, 0, &len, 0, 0);
		ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes, &show);
		if (!ri) {
			dlog (DEBUG1, "OPSB: Got IP for %s -> %s", scandata->who, show);
			if (a->nrrs > 1) {
				irc_chanalert (opsb_bot, "Warning, More than one IP address for %s. Using %s only", scandata->lookup, show);
				if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Warning, More than one IP address for %s. Using %s only", scandata->lookup, show);
			}
			if (inet_aton(show, &scandata->ip) > 0) {
				(void)startscan(scandata);
			} else {
				nlog (LOG_CRITICAL, "OPSB: dns_callback() GETNICKIP failed-> %s", show);
				irc_chanalert (opsb_bot, "Warning, Couldn't get the address for %s", scandata->who);
				ns_free(scandata);
				checkqueue();
			}
		} else {
			nlog (LOG_CRITICAL, "OPSB: dns_callback GETNICKIP rr_info failed");
			irc_chanalert (opsb_bot, "Warning, Couldnt get the address for %s. rr_info failed", scandata->who); 
			ns_free(scandata);
			checkqueue();
		}
		ns_free(show);
		return;			
	} else {
		nlog (LOG_CRITICAL, "OPSP() Answer is Empty!");
		ns_free(scandata);
	}
}

/** @brief ModInit
 *
 *  Init handler
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ModInit( void )
{
	DBAFetchConfigInt ("Confed", &opsb.confed);
	ModuleConfig (opsb_settings);
	/* we have to be careful here. Currently, we have SCAN_SOCKET_COUNT sockets that get opened per connection. Soooo.
	*  we check that MAX_SCANS is not greater than the maxsockets available / SCAN_SOCKET_COUNT
	*  this way, we *shouldn't* get problems with running out of sockets 
	*/
	if (MAX_SCANS > me.maxsocks / SCAN_SOCKET_COUNT) {
		opsbl = list_create(me.maxsocks /SCAN_SOCKET_COUNT);
		opsb.socks = me.maxsocks /SCAN_SOCKET_COUNT;
	} else {
		opsbl = list_create(MAX_SCANS);
		opsb.socks = MAX_SCANS;
	}
	/* queue can be anything we want */
	opsbq = list_create(MAX_QUEUE);
	cache = list_create(opsb.cachesize);
	opsb.ports = list_create(MAX_PORTS);
	opsb.open = 0;
	opsb.scanned = 0;
	opsb.cachehits = 0;
	if( load_ports() != NS_SUCCESS )
	{
		nlog (LOG_WARNING, "Can't Load opsb. No Ports Defined for Scanner. Did you install Correctly?");
		return NS_FAILURE;
	}
	return NS_SUCCESS;
}

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
	if (strlen(opsb.targetip) == 0)
	{
		strlcpy(opsb.targetip, inet_ntoa(me.srvip.sin_addr), MAXHOST);
	}
	if (init_scanengine() != NS_SUCCESS) {
		return NS_FAILURE;
	}
	opsb_bot = AddBot (&opsb_botinfo);
	if (opsb.confed == 0) {
		AddTimer (TIMER_TYPE_INTERVAL, unconf, "unconf", TS_ONE_MINUTE, NULL);
		(void)unconf( NULL );
	}
	if(opsb.verbose) {
		irc_chanalert (opsb_bot, "Open Proxy Scanning bot has started (Concurrent Scans: %d Sockets %d)", opsb.socks, opsb.socks *SCAN_SOCKET_COUNT);
	}
	return NS_SUCCESS;
}

/** @brief ModFini
 *
 *  Fini handler
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ModFini( void )
{
	return NS_SUCCESS;
}
