/* NeoStats - IRC Statistical Services Copyright (c) 1999-2004 NeoStats Group Inc.
** Copyright (c) 1999-2004 Adam Rutter, Justin Hammond
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include "neostats.h"
#include "opsb.h"
#include "opm.h"
#include "opm_types.h"
#include "opm_error.h"

int proxy_connect(unsigned long ipaddr, int port, char *who);
void open_proxy(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void negfailed(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void timeout(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void scan_end(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused);
void scan_error(OPM_T *scanner, OPM_REMOTE_T *remote, int opmerr, void *unused);

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
   
   
OPM_T *scanner;
   
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
		if (!strcasecmp(proxy_list[i].name, name)) {
			return proxy_list[i].type;
		}
	}
	return 0;
}
void add_port(int type, int port) {
	opm_addtype(scanner, type, port);
}

int load_ports() {
	char *portname, **av;
	int i, j, ac, ok;
	port_list *prtlst;
	lnode_t *pn;
	
	ok = 0;
	for (i = 0; proxy_list[i].type != 0; i++) {
		if (GetConf((void *)&portname, CFGSTR, proxy_list[i].name) <= 0) {
			nlog(LOG_WARNING, LOG_MOD, "Warning, No Ports defined for Protocol %s", proxy_list[i].name);
		} else {
			ac = split_buf(portname, &av, 0);
			for (j = 0; j < ac; j++) {
				if (atoi(av[j]) == 0) {
					nlog(LOG_WARNING, LOG_MOD, "Invalid Port %s for Proxy Type %s", av[j], proxy_list[i].name);
					continue;
				}
				if (list_isfull(opsb.ports)) {
					nlog(LOG_MOD, LOG_WARNING, "Ports List is Full.");
					break;
				}
				prtlst = malloc(sizeof(port_list));
				prtlst->type = proxy_list[i].type;
				prtlst->port = atoi(av[j]);
				prtlst->noopen = 0;
				pn = lnode_create(prtlst);
				list_append(opsb.ports, pn);
				nlog(LOG_DEBUG1, LOG_MOD, "Added Port %d for Protocol %s", prtlst->port, proxy_list[i].name);
				ok = 1;
			}
			free(av);
			free(portname);
		}
	}
	return ok;				
}

int init_libopm() {
	lnode_t *pn;
	port_list *pl;
	struct hostent *hp;

	scanner = opm_create();
	/* setup the callbacks to our code */
	opm_callback(scanner, OPM_CALLBACK_OPENPROXY, &open_proxy, NULL);
	opm_callback(scanner, OPM_CALLBACK_NEGFAIL, &negfailed, NULL);
	opm_callback(scanner, OPM_CALLBACK_TIMEOUT, &timeout, NULL);
      	opm_callback(scanner, OPM_CALLBACK_END, &scan_end, NULL);
        opm_callback(scanner, OPM_CALLBACK_ERROR, &scan_error, NULL);
	

	/* configure opm to bind to a IP address */
	if (me.local[0] != 0) {
		if ((hp = gethostbyname(me.local)) == NULL) {
			nlog(LOG_WARNING, LOG_MOD, "Warning, Couldn't bind OPSB ports to IP address: %s", me.local);
		} else {
			if (opm_config(scanner, OPM_CONFIG_BIND_IP, &me.local) != OPM_SUCCESS) {
				nlog(LOG_WARNING, LOG_MOD, "LIBOPM couldn't bind to a IP address");
			}
		}
	}	

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
	add_sockpoll("libopm_before_poll", "libopm_after_poll", "opsb", "opsb", scanner);        
        
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

	nlog(LOG_CRITICAL, LOG_MOD, "OPSB: Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, remote->ip, type_of_proxy(remote->protocol), remote->port);
	chanalert(s_opsb, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, remote->ip, type_of_proxy(remote->protocol), remote->port);
	globops(s_opsb, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, remote->ip, type_of_proxy(remote->protocol), remote->port);
	if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, remote->ip, type_of_proxy(remote->protocol), remote->port);
	if (opsb.doban) sakill_cmd(remote->ip, "*", s_opsb, opsb.bantime, "Open Proxy found on your host. %s(%d)", type_of_proxy(remote->protocol), remote->port);
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
		nlog(LOG_CRITICAL, LOG_MOD, "OPSB: Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
		chanalert(s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
		globops(s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
		if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
		sakill_cmd(inet_ntoa(scandata->ipaddr), "*", s_opsb, opsb.bantime, "Your host is listed as an Open Proxy. Please visit the following website for more info: www.blitzed.org/proxy?ip=%s", inet_ntoa(scandata->ipaddr));
	}	
#endif
}

void negfailed(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;
	
	if (scandata->u) {
		prefmsg(scandata->u->nick, s_opsb, "Negitiation failed for protocol %s(%d)", type_of_proxy(remote->protocol), remote->port);
	}
}	

void timeout(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;
	if (scandata->u) {
		prefmsg(scandata->u->nick, s_opsb, "Timeout on Protocol %s(%d)", type_of_proxy(remote->protocol), remote->port);
	}
}

void scan_end(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;
	if (scandata->u) {
		prefmsg(scandata->u->nick, s_opsb, "scan finished on %s", scandata->who);
	}
	opm_remote_free(remote);
	if (scandata->state != GOTOPENPROXY) scandata->state = FIN_SCAN;
	check_scan_free(scandata);
}

void scan_error(OPM_T *scanner, OPM_REMOTE_T *remote, int opmerr, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();
	scandata = remote->data;
	if (scandata->u) {
		if (opmerr == 5) {
			prefmsg(scandata->u->nick, s_opsb, "Closed Proxy on Protocol %s (%d)", type_of_proxy(remote->protocol), remote->port);
		} else {
			prefmsg(scandata->u->nick, s_opsb, "scan error on Protocol %s (%d) - %d", type_of_proxy(remote->protocol), remote->port, opmerr);
		}
	}

}



int do_status(User *u, char **av, int ac) 
{
	lnode_t *node;
	scaninfo *scandata;

	SET_SEGV_LOCATION();
	
	prefmsg(u->nick, s_opsb, "Proxy Results:");
	prefmsg(u->nick, s_opsb, "Hosts Scanned: %d Hosts found Open: %d Exceptions %d", opsb.scanned, opsb.open, (int)list_count(exempt));
	prefmsg(u->nick, s_opsb, "Cache Entries: %d", (int)list_count(cache));
	prefmsg(u->nick, s_opsb, "Cache Hits: %d", opsb.cachehits);
	prefmsg(u->nick, s_opsb, "Blacklist Hits: %d", opsb.opmhits);
#if 0
	for (i = 0; i < NUM_PROXIES; i++) {
		prefmsg(u->nick, s_opsb, "Proxy %s (%d) Found %d Open %d", proxy_list[i].type, proxy_list[i].port, proxy_list[i].nofound, proxy_list[i].noopen);
	}
#endif
	prefmsg(u->nick, s_opsb, "Currently Scanning %d Proxies (%d in queue):", (int)list_count(opsbl), (int)list_count(opsbq));
	node = list_first(opsbl);
	while (node) {
		scandata = lnode_get(node);
		if (scandata->u) 
			prefmsg(u->nick, s_opsb, "Scanning %s by request of %s", scandata->lookup, scandata->u->nick);
		else 
			prefmsg(u->nick, s_opsb, "Scanning %s (%s) - %s", scandata->lookup, inet_ntoa(scandata->ipaddr), scandata->who);
		
		switch(scandata->dnsstate) {
			case REPORT_DNS:
					prefmsg(u->nick, s_opsb, "Looking up IP Address");
					break;
			case DO_DNS_HOST_LOOKUP:
					prefmsg(u->nick, s_opsb, "Looking up IP address for Scan");
					break;
			case DO_OPM_LOOKUP:
					prefmsg(u->nick, s_opsb, "Looking up DNS blacklist");
					break;
			case OPMLIST:
					prefmsg(u->nick, s_opsb, "Host is listed in %s", opsb.opmdomain);
					break;
			case NOOPMLIST:
					prefmsg(u->nick, s_opsb, "Host is Not listed in %s", opsb.opmdomain);
					break;
			default:
					prefmsg(u->nick, s_opsb, "Unknown State (DNS)");
		}
		switch(scandata->state) {
			case DOING_SCAN:
					prefmsg(u->nick, s_opsb, "Scanning for Open Proxies");
					break;
			case GOTOPENPROXY:
					prefmsg(u->nick, s_opsb, "Contains an Open Proxy");
					break;
			default:
					prefmsg(u->nick, s_opsb, "Unknown State (Scan)");
		}
	node = list_next(opsbl, node);
	}
	return 0;
}


void start_proxy_scan(lnode_t *scannode) {
	scaninfo *scandata;
	OPM_REMOTE_T *remote;
	int i;

	SET_SEGV_LOCATION();


	scandata = lnode_get(scannode);
	/* if we are configured not to scan, and its not a request, bail out */
	if ((opsb.doscan == 0) && (!scandata->u)) {
		scandata->state = FIN_SCAN;
		check_scan_free(scandata);
		return;
	}

	if (scandata->u) chanalert(s_opsb, "Starting proxy scan on %s (%s) by Request of %s", scandata->who, scandata->lookup, scandata->u->nick);
	scandata->state = DOING_SCAN;
	/* this is so we can timeout scans */
	scandata->started = time(NULL);

	if ((opsb.doscan == 1) || (scandata->u)) {
		remote  = opm_remote_create(inet_ntoa(scandata->ipaddr));
		remote->data = scandata;
	   	switch(i = opm_scan(scanner, remote))
      		{
            		case OPM_SUCCESS:
				nlog(LOG_DEBUG2, LOG_MOD, "Starting Scan on %s", inet_ntoa(scandata->ipaddr));
                        	break;
                        case OPM_ERR_BADADDR:
				nlog(LOG_WARNING, LOG_MOD, "Scan of %s %s Failed. Bad Address?", scandata->who, inet_ntoa(scandata->ipaddr));
                                opm_remote_free(remote);
				scandata->state = FIN_SCAN;
				check_scan_free(scandata);
                }
	}

}
void check_scan_free(scaninfo *scandata) {
	lnode_t *scannode;
	if ((scandata->dnsstate == DO_OPM_LOOKUP) || (scandata->dnsstate == DO_DNS_HOST_LOOKUP) || (scandata->state == DOING_SCAN)) {
		nlog(LOG_DEBUG2, LOG_MOD, "Not Cleaning up Scaninfo for %s yet. Scan hasn't completed", scandata->who);
		return;
	}
	if ((scandata->dnsstate != OPMLIST) && (scandata->state != GOTOPENPROXY)) {
		addtocache(scandata->ipaddr.s_addr);	
		nlog(LOG_DEBUG1, LOG_MOD, "%s's Host is clean. Adding to Cache", scandata->who);
	}
	scannode = list_find(opsbl, scandata->who, findscan);
	if (scannode) {
		nlog(LOG_DEBUG1, LOG_MOD, "%s scan finished. Cleaning up", scandata->who);
		list_delete(opsbl, scannode);
		lnode_destroy(scannode);
		scandata->u = NULL;
		free(scandata);
	} else {
		nlog(LOG_WARNING, LOG_MOD, "Damn, Can't find ScanNode %s. Something is fubar", scandata->who);
	}
	checkqueue();												
}
