/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2005 Adam Rutter, Justin Hammond, Mark Hetherington
** http://www.neostats.net/
**
**  Portions Copyright (c) 2004 Erik Fears
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
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include "opsb.h"

int proxy_connect(unsigned long ip, int port, char *who);
#if 0
void open_proxy(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void negfailed(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void timeout(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void scan_end(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void scan_error(OPM_T *scanner, OPM_REMOTE_T *remote, int opmerr, void *unused);
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct conninfo {
	int type;
	int port;
	scaninfo *scandata;
	int status;
};
   
#define PTYPE_HTTP 	0
#define PTYPE_SOCKS4 	1 
#define PTYPE_SOCKS5	2
#define PTYPE_WINGATE	3
#define PTYPE_ROUTER	4
#define PTYPE_HTTPPOST	5

char *defaultports[] = {
	"80 8080 8000 3128",
	"1080",
	"1080",
	"23",
	"23",
	"80 8080 8000 3128",
};

proxy_type proxy_list[] = {
	{ PTYPE_HTTP, "HTTP" },
	{ PTYPE_SOCKS4, "SOCKS4" },
	{ PTYPE_SOCKS5, "SOCKS5" },
	{ PTYPE_WINGATE, "WINGATE" },
	{ PTYPE_ROUTER, "ROUTER"},
	{ PTYPE_HTTPPOST, "HTTPPOST" },
	{ 0, "" }
};

char *type_of_proxy(int type) {
	return proxy_list[type-1].name;
}
int get_proxy_by_name(const char *name) {
	int i;
	for (i=0; proxy_list[i].type != 0; i++) {
		if (!ircstrcasecmp (proxy_list[i].name, name)) {
			return proxy_list[i].type;
		}
	}
	return 0;
}

void save_ports() 
{
	lnode_t *pn;
	port_list *pl;
	static char ports[512];
	static char tmpports[512];
	int lasttype = -1;
	pn = list_first(opsb.ports);
	while (pn) {
		pl = lnode_get(pn);
		/* if the port is different from the last round, and its not the first round, save it */
		if ((pl->type != lasttype) && (lasttype != -1)) {
			DBAStoreConfigStr(type_of_proxy(lasttype), ports, 512);
		} 
		if (pl->type != lasttype) {
			ircsnprintf(ports, 512, "%d", pl->port);
		} else {
			ircsnprintf(tmpports, 512, "%s %d", ports, pl->port);
			strlcpy(ports, tmpports, 512);
		}
		lasttype = pl->type;
		pn = list_next(opsb.ports, pn);
	}
	DBAStoreConfigStr(type_of_proxy(lasttype), ports, 512);
} 

void load_port(char *type, char *portname)
{
	static char portlist[512];
	char **av;
	int j, ac;
	port_list *prtlst;

	strlcpy (portlist, portname, 512);
	ac = split_buf(portlist, &av, 0);
	for (j = 0; j < ac; j++) {
		if (atoi(av[j]) == 0) {
			nlog (LOG_WARNING, "Invalid port %s for proxy type %s", av[j], type);
			continue;
		}
		if (list_isfull(opsb.ports)) {
			nlog (LOG_WARNING, "Ports list is full.");
			break;
		}
		prtlst = malloc(sizeof(port_list));
		prtlst->type = proxy_list[j].type;
		prtlst->port = atoi(av[j]);
		prtlst->noopen = 0;
		lnode_create_append (opsb.ports, prtlst);
		dlog (DEBUG1, "Added port %d for protocol %s", prtlst->port, proxy_list[j].name);
	}
	ns_free(av);
}

int load_ports() {
	static char portname[512];
	int i;
	int ok = 0;
	
	for (i = 0; proxy_list[i].type != 0; i++) {
		if (DBAFetchConfigStr (proxy_list[i].name, portname, 512) != NS_SUCCESS) {
			nlog (LOG_WARNING, "Warning, no ports defined for protocol %s, using defaults", proxy_list[i].name);
			load_port(proxy_list[i].name, defaultports[i]);
			DBAStoreConfigStr(proxy_list[i].name, defaultports[i], 512);
			ok = 1;
		} else {
			load_port(proxy_list[i].name, portname);
			ok = 1;
		}
	}
	return ok;				
}

int init_libopm() {
	return NS_SUCCESS;
}         

void start_proxy_scan(scaninfo *scandata) 
{
	int i;

	SET_SEGV_LOCATION();

	if (scandata->reqclient) irc_chanalert (opsb_bot, "Starting proxy scan on %s (%s) by Request of %s", scandata->who, scandata->lookup, scandata->reqclient->name);
	scandata->state = DOING_SCAN;
	/* this is so we can timeout scans */
	scandata->started = time(NULL);

	
#if 0
	if ((opsb.doscan == 1) || (scandata->reqclient)) {

		remote  = opm_remote_create(inet_ntoa(scandata->ip));
		remote->data = scandata;
	   	switch(i = opm_scan(scanner, remote))
      		{
            		case OPM_SUCCESS:
				dlog (DEBUG2, "Starting Scan on %s", inet_ntoa(scandata->ip));
                        	break;
                        case OPM_ERR_BADADDR:
				nlog (LOG_WARNING, "Scan of %s %s Failed. Bad Address?", scandata->who, inet_ntoa(scandata->ip));
                                opm_remote_free(remote);
				scandata->state = FIN_SCAN;
				check_scan_free(scandata);
                }
	}
#endif
}
void check_scan_free(scaninfo *scandata) {
	lnode_t *scannode;
	if (scandata->state == DOING_SCAN) {
		dlog (DEBUG2, "Not Cleaning up Scaninfo for %s yet. Scan hasn't completed", scandata->who);
		return;
	}
	if (scandata->state != GOTOPENPROXY) {
		addtocache(scandata->ip.s_addr);	
		dlog (DEBUG1, "%s's Host is clean. Adding to Cache", scandata->who);
	}
	scannode = list_find(opsbl, scandata->who, findscan);
	if (scannode) {
		dlog (DEBUG1, "%s scan finished. Cleaning up", scandata->who);
		list_delete(opsbl, scannode);
		lnode_destroy(scannode);
		scandata->reqclient = NULL;
		ns_free(scandata);
	} else {
		nlog (LOG_WARNING, "Damn, Can't find ScanNode %s. Something is fubar", scandata->who);
	}
	checkqueue();												
}



void open_proxy(conninfo *connection)
      {
	scaninfo *scandata = connection->scandata;

	SET_SEGV_LOCATION();

	if (scandata->doneban == 1)
		return;

	++opsb.open;

	nlog (LOG_CRITICAL, "OPSB: Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, scandata->ip, type_of_proxy(connection->type), connection->port);
	irc_chanalert (opsb_bot, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, scandata->ip, type_of_proxy(connection->type), connection->port);
	irc_globops  (opsb_bot, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, scandata->ip, type_of_proxy(connection->type), connection->port);
	if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, scandata->ip, type_of_proxy(connection->type), connection->port);
	if (opsb.doakill) 
		irc_akill (opsb_bot, remote->ip, "*", opsb.akilltime, "Open Proxy found on your host. %s(%d)", type_of_proxy(connection->type), connection->port);

	/* no point continuing the scan if they are found open */
	scandata->state = GOTOPENPROXY;
	/* XXX end scan */
	
}

int opsb_cmd_status (CmdParams* cmdparams) 
{
	lnode_t *node;
	scaninfo *scandata;

	SET_SEGV_LOCATION();
	
	irc_prefmsg (opsb_bot, cmdparams->source, "Proxy Results:");
	irc_prefmsg (opsb_bot, cmdparams->source, "Hosts Scanned: %d Hosts found Open: %d", opsb.scanned, opsb.open);
	irc_prefmsg (opsb_bot, cmdparams->source, "Cache Entries: %d", (int)list_count(cache));
	irc_prefmsg (opsb_bot, cmdparams->source, "Cache Hits: %d", opsb.cachehits);
	irc_prefmsg (opsb_bot, cmdparams->source, "Blacklist Hits: %d", opsb.opmhits);
#if 0
	for (i = 0; i < NUM_PROXIES; i++) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Proxy %s (%d) Found %d Open %d", proxy_list[i].type, proxy_list[i].port, proxy_list[i].nofound, proxy_list[i].noopen);
	}
#endif
	irc_prefmsg (opsb_bot, cmdparams->source, "Currently Scanning %d Proxies (%d in queue):", (int)list_count(opsbl), (int)list_count(opsbq));
	node = list_first(opsbl);
	while (node) {
		scandata = lnode_get(node);
		if (scandata->reqclient) 
			irc_prefmsg (opsb_bot, cmdparams->source, "Scanning %s by request of %s", scandata->lookup, scandata->reqclient->name);
		else 
			irc_prefmsg (opsb_bot, cmdparams->source, "Scanning %s (%s) - %s", scandata->lookup, inet_ntoa(scandata->ip), scandata->who);
		
		switch(scandata->state) {
			case DOING_SCAN:
					irc_prefmsg (opsb_bot, cmdparams->source, "Scanning for Open Proxies");
					break;
			case GOTOPENPROXY:
					irc_prefmsg (opsb_bot, cmdparams->source, "Contains an Open Proxy");
					break;
			default:
					irc_prefmsg (opsb_bot, cmdparams->source, "Unknown State (Scan)");
		}
	node = list_next(opsbl, node);
	}
	return 0;
}


