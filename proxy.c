/* NeoStats - IRC Statistical Services Copyright (c) 1999-2002 NeoStats Group Inc.
** Copyright (c) 1999-2002 Adam Rutter, Justin Hammond
** http://www.neostats.net/
**
**  Portions Copyright (c) 2002 Erik Fears
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
#include <fcntl.h>
#include "dl.h"
#include "stats.h"
#include "opsb.h"
#include "log.h"
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
   


int init_libopm() {

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
	
	opm_addtype(scanner, OPM_TYPE_HTTP, 8080);        


	/* add the sock poll interface into neo */
	add_sockpoll("libopm_before_poll", "libopm_after_poll", "opsb", "opsb", scanner);        
        
        return 1;
}         

void open_proxy(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused)
      {
	FILE *fp;
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;

	if (scandata->doneban == 1)
		return;

	++opsb.open;

	nlog(LOG_CRITICAL, LOG_MOD, "OPSB: Banning %s (%s) for Open Proxy - %d(%d)", scandata->who, remote->ip, remote->protocol, remote->port);
	chanalert(s_opsb, "Banning %s (%s) for Open Proxy - %d(%d)", scandata->who, remote->ip, remote->protocol, remote->port);
	globops(s_opsb, "Banning %s (%s) for Open Proxy - %d(%d)", scandata->who, remote->ip, remote->protocol, remote->port);
	if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Banning %s (%s) for Open Proxy - %d(%d)", scandata->who, remote->ip, remote->protocol, remote->port);
#if 0
	sakill_cmd(remote->ip, "*", s_opsb, opsb.bantime, "Open Proxy found on your host. %d(%d)", remote->protocol, remote->port);

	/* write out to a logfile */
	if ((fp = fopen("logs/openproxies.log", "a")) == NULL) return;
	fprintf(fp, "%d:%s:%s\n", remote->protocol, remote->ip, "empty");
        fclose(fp);
#endif
	/* no point continuing the scan if they are found open */
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
		prefmsg(scandata->u->nick, s_opsb, "Negitiation failed for protocol %d (%d)", remote->protocol, remote->port);
	}
	/*XXX Do anything.. I dont think so */
}	

void timeout(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;
	if (scandata->u) {
		prefmsg(scandata->u->nick, s_opsb, "Timeout on Protocol %d (%d)", remote->protocol, remote->port);
	}
	/*XXX Do anything? I don't think so */
}

void scan_end(OPM_T *scanner, OPM_REMOTE_T *remote, int notused, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();

	scandata = remote->data;
	if (scandata->u) {
		prefmsg(scandata->u->nick, s_opsb, "scan finished %d %d", remote->protocol, remote->port);
	}
	/*XXX we have to cleanup here */
}

void scan_error(OPM_T *scanner, OPM_REMOTE_T *remote, int opmerr, void *unused) {
	scaninfo *scandata;

	SET_SEGV_LOCATION();
#if 0
		/* don't delete if the opm lookup hasn't completed yet */
		if ((scandata->dnsstate == DO_OPM_LOOKUP) || (scandata->dnsstate == GET_NICK_IP))
			break;
		
		if (scandata->dnsstate == OPMLIST) savescan = 0;
		/* if this is not valid, exit  (ie, the scan hasn't started yet) */
		if (scandata->socks == NULL) {
			nlog(LOG_CRITICAL, LOG_MOD, "Ehhh, socks for %s is NULL? WTF?", scandata->who);
			break;
		}
#endif
	scandata = remote->data;
	if (scandata->u) {
		prefmsg(scandata->u->nick, s_opsb, "scan error on Protocol %d (%d)", remote->protocol, remote->port);
	}

	/*XXX cleanup */

}



void send_status(User *u) {
	lnode_t *node;
	scaninfo *scandata;

	SET_SEGV_LOCATION();
	
	prefmsg(u->nick, s_opsb, "Proxy Results:");
	prefmsg(u->nick, s_opsb, "Hosts Scanned: %d Hosts found Open: %d Exceptions %d", opsb.scanned, opsb.open, list_count(exempt));
	prefmsg(u->nick, s_opsb, "Cache Entries: %d", list_count(cache));
	prefmsg(u->nick, s_opsb, "Cache Hits: %d", opsb.cachehits);
	prefmsg(u->nick, s_opsb, "Blacklist Hits: %d", opsb.opmhits);
#if 0
	for (i = 0; i < NUM_PROXIES; i++) {
		prefmsg(u->nick, s_opsb, "Proxy %s (%d) Found %d Open %d", proxy_list[i].type, proxy_list[i].port, proxy_list[i].nofound, proxy_list[i].noopen);
	}
#endif
	prefmsg(u->nick, s_opsb, "Currently Scanning %d Proxies (%d in queue):", list_count(opsbl), list_count(opsbq));
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
			case GET_NICK_IP:
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
}


void start_proxy_scan(lnode_t *scannode) {
	scaninfo *scandata;
	OPM_REMOTE_T *remote;
	int i;

	SET_SEGV_LOCATION();


	scandata = lnode_get(scannode);
	if (scandata->u) chanalert(s_opsb, "Starting proxy scan on %s (%s) by Request of %s", scandata->who, scandata->lookup, scandata->u->nick);
	scandata->state = DOING_SCAN;
	/* this is so we can timeout scans */
	scandata->started = time(NULL);

	if ((opsb.doscan == 1) || (scandata->u)) {
		nlog(LOG_DEBUG2, LOG_MOD, "Starting Scan on %s", inet_ntoa(scandata->ipaddr));
		remote  = opm_remote_create(inet_ntoa(scandata->ipaddr));
		remote->data = scandata;
	   	switch(i = opm_scan(scanner, remote))
      		{
            		case OPM_SUCCESS:
                        	break;
                        case OPM_ERR_BADADDR:
                                printf("Bad address\n");
                                opm_remote_free(remote);
				/* XXX do what else ? */
                        default:
                                printf("Unknown Error %d\n", i);
                }
	}

}
