/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2004 Adam Rutter, Justin Hammond, Mark Hetherington
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
#include "opm.h"
#include "opm_types.h"
#include "opm_error.h"

int proxy_connect(unsigned long ip, int port, char *who);
void open_proxy(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void negfailed(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void timeout(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void scan_end(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void scan_error(OPM_T *scanner, OPM_REMOTE_T *remote, int opmerr, void *unused);

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
   
   
OPM_T *scanner;

char *defaultports[] = {
	"80 8080 8000 3128",
	"1080",
	"1080",
	"23",
	"23",
	"80 8080 8000 3128",
};

proxy_type proxy_list[] = {
	{ OPM_TYPE_HTTP, "HTTP" },
	{ OPM_TYPE_SOCKS4, "SOCKS4" },
	{ OPM_TYPE_SOCKS5, "SOCKS5" },
	{ OPM_TYPE_WINGATE, "WINGATE" },
	{ OPM_TYPE_ROUTER, "ROUTER"},
	{ OPM_TYPE_HTTPPOST, "HTTPPOST" },
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
void add_port(int type, int port) {
	opm_addtype(scanner, type, port);
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
	char **av;
	int j, ac;
	port_list *prtlst;

	ac = split_buf(portname, &av, 0);
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
		prtlst->type = proxy_list[i].type;
		prtlst->port = atoi(av[j]);
		prtlst->noopen = 0;
		lnode_create_append (opsb.ports, prtlst);
		dlog (DEBUG1, "Added port %d for protocol %s", prtlst->port, proxy_list[i].name);
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
	lnode_t *pn;
	port_list *pl;

	scanner = opm_create();
	/* setup the callbacks to our code */
	opm_callback(scanner, OPM_CALLBACK_OPENPROXY, &open_proxy, NULL);
	opm_callback(scanner, OPM_CALLBACK_NEGFAIL, &negfailed, NULL);
	opm_callback(scanner, OPM_CALLBACK_TIMEOUT, &timeout, NULL);
      	opm_callback(scanner, OPM_CALLBACK_END, &scan_end, NULL);
        opm_callback(scanner, OPM_CALLBACK_ERROR, &scan_error, NULL);
	
	/* max number of socks we allow */
	opm_config(scanner, OPM_CONFIG_FD_LIMIT, &opsb.socks);
	/* host to try to connect to */
	opm_config(scanner, OPM_CONFIG_SCAN_IP, opsb.targethost);
	/* port to try to connect to */
	opm_config(scanner, OPM_CONFIG_SCAN_PORT, &opsb.targetport);
	/* string to look for */
	opm_config(scanner, OPM_CONFIG_TARGET_STRING, opsb.lookforstring);
	/* also look for throttle messages */
	opm_config(scanner, OPM_CONFIG_TARGET_STRING, "ERROR :Trying to reconnect too fast");
	/* timeout */
	opm_config(scanner, OPM_CONFIG_TIMEOUT, &opsb.timeout);
	/* max bytes read */
	opm_config(scanner, OPM_CONFIG_MAX_READ, &opsb.maxbytes);
	


	/* read the proxy types directly from keeper :) */
	pn = list_first(opsb.ports);
	while (pn) {
		pl = lnode_get(pn);
		opm_addtype(scanner, pl->type, pl->port);
		pn = list_next(opsb.ports, pn);
	}
	       

	/* add the sock poll interface into neo */
	add_sockpoll("opsb", scanner, libopm_before_poll, libopm_after_poll);
        
        return 1;
}         

void open_proxy(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused)
      {
#if 0
	FILE *fp;
#endif
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;

	if (scandata->doneban == 1)
		return;

	++opsb.open;

	nlog (LOG_CRITICAL, "OPSB: Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, remote->ip, type_of_proxy(remote->protocol), remote->port);
	irc_chanalert (opsb_bot, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, remote->ip, type_of_proxy(remote->protocol), remote->port);
	irc_globops  (opsb_bot, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, remote->ip, type_of_proxy(remote->protocol), remote->port);
	if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, remote->ip, type_of_proxy(remote->protocol), remote->port);
	if (opsb.doban) 
		irc_akill (opsb_bot, remote->ip, "*", opsb.bantime, "Open Proxy found on your host. %s(%d)", type_of_proxy(remote->protocol), remote->port);
#if 0
	/* write out to a logfile */
	if ((fp = fopen("logs/openproxies.log", "a")) == NULL) return;
	fprintf(fp, "%d:%s:%s\n", remote->protocol, remote->ip, "empty");
        fclose(fp);
#endif
	/* no point continuing the scan if they are found open */
	scandata->state = GOTOPENPROXY;
	opm_end(scanner, remote);


#if 0
	if (scandata->dnsstate == OPMLIST) {
		scandata->doneban = 1;
		nlog (LOG_CRITICAL, "OPSB: Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ip), opsb.opmdomain);
		irc_chanalert (opsb_bot, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ip), opsb.opmdomain);
		irc_globops  (opsb_bot, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ip), opsb.opmdomain);
		if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ip), opsb.opmdomain);
		irc_akill (opsb_bot, inet_ntoa(scandata->ip), "*", opsb.bantime, "Your host is listed as an Open Proxy. Please visit the following website for more info: www.blitzed.org/proxy?ip=%s", inet_ntoa(scandata->ip));
	}	
#endif
}

void negfailed(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;
	
	if (scandata->reqclient) {
		irc_prefmsg (opsb_bot, scandata->reqclient, "Negitiation failed for protocol %s(%d)", type_of_proxy(remote->protocol), remote->port);
	}
}	

void timeout(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;
	if (scandata->reqclient) {
		irc_prefmsg (opsb_bot, scandata->reqclient, "Timeout on Protocol %s(%d)", type_of_proxy(remote->protocol), remote->port);
	}
}

void scan_end(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;
	if (scandata->reqclient) {
		irc_prefmsg (opsb_bot, scandata->reqclient, "scan finished on %s", scandata->who);
	}
	opm_remote_free(remote);
	if (scandata->state != GOTOPENPROXY) scandata->state = FIN_SCAN;
	check_scan_free(scandata);
}

void scan_error(OPM_T *scanner, OPM_REMOTE_T *remote, int opmerr, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();
	scandata = remote->data;
	if (scandata->reqclient) {
		if (opmerr == 5) {
			irc_prefmsg (opsb_bot, scandata->reqclient, "Closed Proxy on Protocol %s (%d)", type_of_proxy(remote->protocol), remote->port);
		} else {
			irc_prefmsg (opsb_bot, scandata->reqclient, "scan error on Protocol %s (%d) - %d", type_of_proxy(remote->protocol), remote->port, opmerr);
		}
	}

}



int opsb_cmd_status (CmdParams* cmdparams) 
{
	lnode_t *node;
	scaninfo *scandata;

	SET_SEGV_LOCATION();
	
	irc_prefmsg (opsb_bot, cmdparams->source, "Proxy Results:");
	irc_prefmsg (opsb_bot, cmdparams->source, "Hosts Scanned: %d Hosts found Open: %d Exceptions %d", opsb.scanned, opsb.open, GetExemptCount ());
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
		
		switch(scandata->dnsstate) {
			case REPORT_DNS:
					irc_prefmsg (opsb_bot, cmdparams->source, "Looking up IP Address");
					break;
			case DO_DNS_HOST_LOOKUP:
					irc_prefmsg (opsb_bot, cmdparams->source, "Looking up IP address for Scan");
					break;
			case DO_OPM_LOOKUP:
					irc_prefmsg (opsb_bot, cmdparams->source, "Looking up DNS blacklist");
					break;
			case OPMLIST:
					irc_prefmsg (opsb_bot, cmdparams->source, "Host is listed in %s", opsb.opmdomain);
					break;
			case NOOPMLIST:
					irc_prefmsg (opsb_bot, cmdparams->source, "Host is Not listed in %s", opsb.opmdomain);
					break;
			default:
					irc_prefmsg (opsb_bot, cmdparams->source, "Unknown State (DNS)");
		}
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


void start_proxy_scan(scaninfo *scandata) 
{
	OPM_REMOTE_T *remote;
	int i;

	SET_SEGV_LOCATION();
	/* if we are configured not to scan, and its not a request, bail out */
	if ((opsb.doscan == 0) && (!scandata->reqclient)) {
		scandata->state = FIN_SCAN;
		check_scan_free(scandata);
		return;
	}

	if (scandata->reqclient) irc_chanalert (opsb_bot, "Starting proxy scan on %s (%s) by Request of %s", scandata->who, scandata->lookup, scandata->reqclient->name);
	scandata->state = DOING_SCAN;
	/* this is so we can timeout scans */
	scandata->started = time(NULL);

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

}
void check_scan_free(scaninfo *scandata) {
	lnode_t *scannode;
	if ((scandata->dnsstate == DO_OPM_LOOKUP) || (scandata->dnsstate == DO_DNS_HOST_LOOKUP) || (scandata->state == DOING_SCAN)) {
		dlog (DEBUG2, "Not Cleaning up Scaninfo for %s yet. Scan hasn't completed", scandata->who);
		return;
	}
	if ((scandata->dnsstate != OPMLIST) && (scandata->state != GOTOPENPROXY)) {
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
