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
** $Id: proxy.c,v 1.4 2002/09/06 04:33:28 fishwaldo Exp $
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

int proxy_connect(unsigned long ipaddr, int port, char *who);
int http_proxy(int sock);
int sock4_proxy(int sock);
int sock5_proxy(int sock);
int cisco_proxy(int sock);
int wingate_proxy(int sock);


#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif


proxy_types proxy_list[] = {
	{"http", 	80, 	http_proxy, 	0,	0},
	{"http",	8080,	http_proxy,	0,	0},
	{"http",	3128,	http_proxy, 	0,	0},
	{"socks4",	1080,	sock4_proxy,	0,	0},
	{"socks5",	1080,	sock5_proxy,	0,	0},
	{"Cisco",	23,	cisco_proxy, 	0,	0},
	{"Wingate",	23,	wingate_proxy,	0,	0},
	{NULL,		0,	NULL,		0,	0}
};

#define NUM_PROXIES 7


void do_ban(scaninfo *scandata) {
	lnode_t *socknode;
	socklist *sockdata;
	FILE *fp;

	strcpy(segv_location, "OPSB:dns_lookup");

	if (scandata->doneban == 1)
		return;
	

	++opsb.open;

	
	/* ban based on proxy detection first */
	socknode = list_first(scandata->socks);
	while (socknode) {
		sockdata = lnode_get(socknode);
		if (sockdata->flags !=	OPENPROXY) {
			socknode = list_next(scandata->socks, socknode);
			break;
		}
		scandata->doneban = 1;
		log("OPSB: Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, inet_ntoa(scandata->ipaddr), proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
		chanalert(s_opsb, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, inet_ntoa(scandata->ipaddr), proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
		globops(s_opsb, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, inet_ntoa(scandata->ipaddr), proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
		if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, inet_ntoa(scandata->ipaddr), proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
		sakill_cmd(inet_ntoa(scandata->ipaddr), "*", s_opsb, opsb.bantime, "Open Proxy found on your host. Please visit the following website for more info: www.blitzed.org/proxy?ip=%s", inet_ntoa(scandata->ipaddr));
		if ((fp = fopen("logs/opsb.log", "a")) == NULL) return;
       		fprintf(fp, "%s: %s\n", proxy_list[sockdata->type].type, inet_ntoa(scandata->ipaddr));
                fclose(fp);
		socknode = list_next(scandata->socks, socknode);
	}
	if (scandata->dnsstate == OPMLIST) {
		scandata->doneban = 1;
		log("OPSB: Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
		chanalert(s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
		globops(s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
		if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Banning %s (%s) as its listed in %s", scandata->who, inet_ntoa(scandata->ipaddr), opsb.opmdomain);
		sakill_cmd(inet_ntoa(scandata->ipaddr), "*", s_opsb, opsb.bantime, "Your host is listed as a Open Proxy. Please visit the following website for more info: www.blitzed.org/proxy?ip=%s", inet_ntoa(scandata->ipaddr));
	}	

}






scaninfo *find_scandata(char *sockname) {
	char *buf, *cmd;
	lnode_t *scannode;
	
	buf = sstrdup(sockname);
	cmd = strtok(buf, " ");

	scannode = list_find(opsbl, cmd, findscan);
	free(buf);
	if (scannode)
		return lnode_get(scannode);
	else 
		return NULL;
}
void cleanlist() {
	lnode_t *scannode;
	scaninfo *scandata;
	lnode_t *socknode, *scannode2;
	socklist *sockdata;
	char sockname[64];
	int savescan, timedout = 0, finished;

	strcpy(segv_location, "OPSB:cleanlist");

	scannode = list_first(opsbl);
	while (scannode) {
		timedout = 0;
		scandata = lnode_get(scannode);
		/* check if this scan has timed out */
		if (time(NULL) - scandata->started > opsb.timeout) timedout = 1;

		/* savescan is a flag if we should save this entry into the cache file */
		savescan = 1;	
		
		if (scandata->dnsstate == OPMLIST) savescan = 0;
		/* if this is not valid, exit  (ie, the scan hasn't started yet) */
		if (scandata->socks == NULL) break;
		/* check for open sockets */
		socknode = list_first(scandata->socks);	
		finished = 1;
		while (socknode) {
			
			sockdata = lnode_get(socknode);
			/* if it was a open proxy, don't save the cache */
			if (sockdata->flags == OPENPROXY) savescan = 0;

			/* if this still has sockets connected, set finished flaged to 0 to not delete scans */
			if ((sockdata->flags == SOCKCONNECTED) || (sockdata->flags == CONNECTING)) finished = 0;
			if (timedout == 1) {
				if ((sockdata->flags == SOCKCONNECTED) || (sockdata->flags == CONNECTING))  {
					/* it still has open socks */
					snprintf(sockname, 64, "%s %d", scandata->who, sockdata->type);
					sockdata->flags = UNCONNECTED;
#ifdef DEBUG	
					log("Closing Socket %s in cleanlist function for timeout()", sockname);
#endif	
					if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Timeout Connecting to Proxy %s on port %d", proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
		
					sock_disconnect(sockname);
				}
				/* free the socket struct as its timed out and un-connected by now */
		
			}  
			socknode = list_next(scandata->socks, socknode);
		}

		if (timedout == 1 || finished == 1) {
#ifdef DEBUG
			if (timedout == 1) log("Deleting Old Scannode %s out of active list (Timeout)", scandata->who );
			if (finished == 1) log("Deleting Old Scannode %s out of active list (Finished)", scandata->who );
#endif
			if (savescan == 1) 
				addtocache(scandata->ipaddr.s_addr);

			/* destory all the nodes in the sock list */
			if (scandata->socks != NULL) {
				socknode = list_first(scandata->socks);
				while (socknode) {
					sockdata = lnode_get(socknode);
#ifdef DEBUG	
					log("freeing sockdata %s %d", scandata->who, sockdata->type);
#endif
					free(sockdata);
					socknode = list_next(scandata->socks, socknode);
				}
				list_destroy_nodes(scandata->socks);
			}	
			scannode2 = list_next(opsbl, scannode);
			list_delete(opsbl, scannode);
			lnode_destroy(scannode);
			scandata->u = NULL;
			free(scandata);
			scannode = scannode2;							
		} else {
			scannode = list_next(opsbl, scannode);					
		}
	}
	checkqueue();
}


void send_status(User *u) {
	int i;
	lnode_t *node, *socknode;
	scaninfo *scandata;
	socklist *sockinfo;

	strcpy(segv_location, "OPSB:send_status");
	
	prefmsg(u->nick, s_opsb, "Proxy Results:");
	prefmsg(u->nick, s_opsb, "Hosts Scanned: %d Hosts found Open: %d Exceptions %d", opsb.scanned, opsb.open, list_count(exempt));
	prefmsg(u->nick, s_opsb, "Cache Entries: %d", list_count(cache));
	for (i = 0; i < NUM_PROXIES; i++) {
		prefmsg(u->nick, s_opsb, "Proxy %s (%d) Found %d Open %d", proxy_list[i].type, proxy_list[i].port, proxy_list[i].nofound, proxy_list[i].noopen);
	}
	prefmsg(u->nick, s_opsb, "Currently Scanning %d Proxies (%d in queue):", list_count(opsbl), list_count(opsbq));
	node = list_first(opsbl);
	while (node) {
		scandata = lnode_get(node);
		if (scandata->u) 
			prefmsg(u->nick, s_opsb, "Scanning %s by request of %s", scandata->lookup, scandata->u->nick);
		else 
			prefmsg(u->nick, s_opsb, "Scanning %s (%s)", scandata->lookup, inet_ntoa(scandata->ipaddr));
		
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
					prefmsg(u->nick, s_opsb, "Contains a Open Proxy");
					break;
			default:
					prefmsg(u->nick, s_opsb, "Unknown State (Scan)");
		}
		socknode = list_first(scandata->socks);
		while (socknode) {
			sockinfo = lnode_get(socknode);
			switch (sockinfo->flags) {
				case CONNECTING:
						prefmsg(u->nick, s_opsb, "    %s(%d) - Connecting", proxy_list[sockinfo->type].type, proxy_list[sockinfo->type].port);
						break;
				case SOCKCONNECTED:
						prefmsg(u->nick, s_opsb, "    %s(%d) - Connected", proxy_list[sockinfo->type].type, proxy_list[sockinfo->type].port);
						break;
				case UNCONNECTED:
						prefmsg(u->nick, s_opsb, "    %s(%d) - Disconnected", proxy_list[sockinfo->type].type, proxy_list[sockinfo->type].port);
						break;
				case OPENPROXY:
						prefmsg(u->nick, s_opsb, "    %s(%d) - Open Proxy", proxy_list[sockinfo->type].type, proxy_list[sockinfo->type].port);
						break;
				default:
						prefmsg(u->nick, s_opsb, "    %s(%d) - Unknown", proxy_list[sockinfo->type].type, proxy_list[sockinfo->type].port);
			}
			socknode = list_next(scandata->socks, socknode);
		}
	node = list_next(opsbl, node);
	}
}


void start_proxy_scan(lnode_t *scannode) {
	scaninfo *scandata;
	socklist *sockdata;
	lnode_t *socknode;
	char *sockname;
	int i, j;

	strcpy(segv_location, "OPSB:start_proxy_scan");


	scandata = lnode_get(scannode);
	if (scandata->u) chanalert(s_opsb, "Starting proxy scan on %s (%s) by Request of %s", scandata->who, scandata->lookup, scandata->u->nick);
	scandata->socks = list_create(NUM_PROXIES);
	scandata->state = DOING_SCAN;
	for (i = 0; i <  NUM_PROXIES; i++) {
#ifdef DEBUG	
		log("OPSB proxy_connect(): host %ul (%s), port %d", scandata->ipaddr,inet_ntoa(scandata->ipaddr), proxy_list[i].port);
#endif
		sockname = malloc(64);
		sprintf(sockname, "%s %d", scandata->who, i);
		j = proxy_connect(scandata->ipaddr.s_addr, proxy_list[i].port, sockname);
		free(sockname);
		if (j > 0) {
			/* its ok */
			sockdata = malloc(sizeof(socklist));
			sockdata->sock = j;
			sockdata->function = proxy_list[i].scan;
			sockdata->flags = CONNECTING;
			sockdata->type = i;
			sockdata->bytes = 0;
			socknode = lnode_create(sockdata);
			list_append(scandata->socks, socknode);
		}
	}
	/* this is so we can timeout scans */
	scandata->started = time(NULL);
}

/* the following functions (http_proxy, sock4_proxy, sock5_proxy, cisco_proxy and wingate_proxy
** were borrowed from the BOPM proxy scanning bot. 
** This code is Copyrighted by Erik Fears (strtok@blitzed.org) and is used with thanks
** this code is used under the GPL license, as the original BOPM is licensed under
*/


int http_proxy(int sock) {
	char *buf;
	int i;
	buf = malloc(512);
	i = snprintf(buf, 512, "CONNECT %s:%d HTTP/1.0\r\n\r\n", opsb.targethost, opsb.targetport);
#ifdef DEBUG
	log("sending http request");
#endif
	i= send(sock, buf, i, MSG_NOSIGNAL);
	free(buf);
	return i;
}


int sock4_proxy(int sock) {
	struct in_addr addr;
	unsigned long laddr;
	char *buf;
	int len;
 
	if (inet_aton(opsb.targethost, &addr) == 0) {
		log("OPSB socks4_proxy() : %s is not a valid IP",
		    opsb.targethost);
	    	return 0;
	}
    
	laddr = htonl(addr.s_addr);
 	buf = malloc(512);
	len = snprintf(buf, 512, "%c%c%c%c%c%c%c%c%c",  4, 1,
	    (((unsigned short) opsb.targetport) >> 8) & 0xFF,
	    (((unsigned short) opsb.targetport) & 0xff),
	    (char) (laddr >> 24) & 0xFF, (char) (laddr >> 16) & 0xFF,
	    (char) (laddr >> 8) & 0xFF, (char) laddr & 0xFF, 0);
	
	len = send(sock, buf, len, MSG_NOSIGNAL);
	free(buf);
	return(len);
}

int sock5_proxy(int sock) {
        struct in_addr addr;
        unsigned long laddr;
        int len;
        char *buf;

        if (inet_aton(opsb.targethost, &addr) == 0) {
                log("OPSB socks5_proxy() : %s is not a valid IP",
                    opsb.targethost);
        }

        laddr = htonl(addr.s_addr);
	buf = malloc(512);
        /* Form authentication string */
        /* Version 5, 1 number of methods, 0 method (no auth). */
        len = snprintf(buf, 512, "%c%c%c", 5, 1, 0);
        len = send(sock, buf, len, MSG_NOSIGNAL);
	if (len < 0) {
		free(buf);
		return len;
	}
        /* Form request string */

        len = snprintf(buf, 512, "%c%c%c%c%c%c%c%c%c%c", 5, 1, 0, 1,
            (char) (laddr >> 24) & 0xFF, (char) (laddr >> 16) & 0xFF,
            (char) (laddr >> 8) & 0xFF, (char) laddr & 0xFF,
            (((unsigned short) opsb.targetport) >> 8) & 0xFF,
            (((unsigned short) opsb.targetport) & 0xFF)
                      );

        len = send(sock, buf, len, MSG_NOSIGNAL);
        free(buf);
        return(len);



}


int cisco_proxy(int sock) {
	char *buf;
	int i;
	buf = malloc(512);
	i = snprintf(buf, 512, "cisco\r\n");
	i = send(sock, buf, i, MSG_NOSIGNAL);
	if (i < 0)
		return i;
	i = snprintf(buf, 512, "telnet %s %d\r\n", opsb.targethost, opsb.targetport);
	i = send(sock, buf, i, MSG_NOSIGNAL);
	free(buf);
	return i;
}

int wingate_proxy(int sock) {
	char *buf;
	int i;
	buf = malloc(512);
	i = snprintf(buf, 512, "%s:%d\r\n", opsb.targethost, opsb.targetport);
	i = send(sock, buf, i, MSG_NOSIGNAL);
	free(buf);
	return i;
}



/* proxy read function */

int proxy_read(int socknum, char *sockname) {
	char *buf;
	int i = 0;
	scaninfo *scandata;
	lnode_t	*socknode;
	socklist *sockdata = NULL;

	strcpy(segv_location, "OPSB:proxy_read");

	scandata = find_scandata(sockname);
	if (!scandata) {
		log("ehh, wtf, can find scan data");
		return 1;
	}
	socknode = list_first(scandata->socks);
	while (socknode) {
		sockdata = lnode_get(socknode);
		if (sockdata->sock == socknum) {
			i = 1;
			break;
		}
		socknode = list_next(scandata->socks, socknode);
	}		
	if (i == 0) {
		log("ehh can't find socket info %s (%d) for proxy_read()", sockname, socknum);
		return 1;
	}
	buf = malloc(512);
	bzero(buf, 512);
	i = recv(socknum, buf, 512, 0);
	if (i < 0) {
#ifdef DEBUG
		log("OPSB proxy_read(): %d has the following error: %s", socknum, strerror(errno));
#endif
		if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "No %s Proxy Server on port %d", proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
		sock_disconnect(sockname);
		sockdata->flags = UNCONNECTED;
		free(buf);
		return -1;
	} else {
		if (i > 0) {
#ifdef DEBUG
			log("OPSB proxy_read(): Got this: %s (%d)",buf, i);
#endif
			/* we check if this might be a normal http server */

			if (strstr(buf, "Method Not Allowed")) {
#ifdef DEBUG
				log("closing socket %d due to ok HTTP server", socknum);
#endif
				if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "No Open %s Proxy Server on port %d", proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
				sockdata->flags = UNCONNECTED;
				sock_disconnect(sockname);
				free(buf);
				return -1;
			}
	
			/* this looks for the ban string */
			if (strstr(buf, opsb.lookforstring)) {
				if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "Open %s Proxy Server on port %d", proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
				++proxy_list[sockdata->type].noopen;
				scandata->state = GOTOPENPROXY;
				sockdata->flags = OPENPROXY;
				do_ban(scandata);
				sock_disconnect(sockname);
				free(buf);
				return -1;
			}
			sockdata->bytes += i;
			/* avoid reading too much data */
			if (sockdata->bytes > opsb.maxbytes) {
#ifdef DEBUG
				log("OPSB proxy_read(): Closing %d due to too much data", socknum);
#endif
				if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "No Open %s Proxy Server on port %d", proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
				sock_disconnect(sockname);
				sockdata->flags = UNCONNECTED;
				free(buf);
				return -1;
			}
		}
	}
	free(buf);
	return 1;

}

/* proxy write function */

int proxy_write(int socknum, char *sockname) {
	int i = 0;
	scaninfo *scandata;
	lnode_t	*socknode;
	socklist *sockdata = NULL;

	strcpy(segv_location, "OPSB:proxy_write");


	scandata = find_scandata(sockname);
	if (!scandata) {
		log("ehh, wtf, can find scan data");
		return 1;
	}
	socknode = list_first(scandata->socks);
	while (socknode) {
		sockdata = lnode_get(socknode);
		if (sockdata->sock == socknum) {
			i = 1;
			break;
		}
		socknode = list_next(scandata->socks, socknode);
	}		
	if (i == 0) {
		log("ehhh, can't find socket %s %d for proxy_write()", sockname, socknum);
		return 1;
	}			
	if (sockdata->flags == CONNECTING || sockdata->flags == SOCKCONNECTED) {
	
		if (sockdata->flags == CONNECTING) 
			i = (int)sockdata->function(socknum);
		else 
			i = send(socknum, "", 1, MSG_NOSIGNAL);
		if (i < 0) {
#ifdef DEBUG
			log("OPSB proxy_write(): %d has the following error: %s", socknum, strerror(errno));
#endif
			if (scandata->u) prefmsg(scandata->u->nick, s_opsb, "No %s Proxy Server on port %d", proxy_list[sockdata->type].type, proxy_list[sockdata->type].port);
			sock_disconnect(sockname);
			sockdata->flags = UNCONNECTED;
			return -1;
		} else {
			if (sockdata->flags != SOCKCONNECTED) ++proxy_list[sockdata->type].nofound;
			sockdata->flags = SOCKCONNECTED;
		}
	}
	return 1;
}

/* proxy error function */

int proxy_err(int socknum, char *sockname) {
return 1;
}


/* proxy connect function trys to connect a socket to a remote proxy 
*  its set non blocking, so both the send and recieve functions must be used
*  to tell if the connection is successfull or not
*  it also registers the socket with the core neostats socket functions
*/

int proxy_connect(unsigned long ipaddr, int port, char *who)
{
	int s;
	s = sock_connect(SOCK_STREAM, ipaddr, port, who, "opsb", "proxy_read", "proxy_write", "proxy_err");
	return s;
	
}
