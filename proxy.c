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
#include "event.h"
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
	int status;
	int bytesread;
	OS_SOCKET fd;
	Sock *sock;
	scaninfo *scandata;
} conninfo;
   
#define PTYPE_HTTP 	1
#define PTYPE_SOCKS4 	2 
#define PTYPE_SOCKS5	3
#define PTYPE_WINGATE	4
#define PTYPE_ROUTER	5
#define PTYPE_HTTPPOST	6

char *defaultports[] = {
	"80 8080 8000 3128",
	"1080",
	"1080",
	"23",
	"23",
	"80 8080 8000 3128",
};

char *stdmatchstrings[] = {
	"*Looking up your hostname*",
	"*You have not registered*",
	"*HTTP/1.0 200 Connection established*",
	NULL
};

int http_send (int fd, void *data);
int sock4_send(int fd, void *data);
int sock5_send(int fd, void *data);
int wingate_send(int fd, void *data);
int router_send(int fd, void *data);
int httppost_send(int fd, void *data);
int proxy_read(void *data, void *recv, size_t size);
void open_proxy(conninfo *connection);


proxy_type proxy_list[] = {
	{ PTYPE_HTTP, "HTTP",  http_send},
	{ PTYPE_SOCKS4, "SOCKS4", sock4_send },
	{ PTYPE_SOCKS5, "SOCKS5", sock5_send },
	{ PTYPE_WINGATE, "WINGATE", wingate_send},
	{ PTYPE_ROUTER, "ROUTER", router_send},
	{ PTYPE_HTTPPOST, "HTTPPOST", httppost_send},
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

char http_send_buf[BUFSIZE];
int http_send_buf_len;
char httppost_send_buf[BUFSIZE];
int httppost_send_buf_len;
char router_send_buf[BUFSIZE];
int router_send_buf_len;
char wingate_send_buf[BUFSIZE];
int wingate_send_buf_len;
char socks4_send_buf[BUFSIZE];
int socks4_send_buf_len;
char socks5_send_buf[BUFSIZE];
int socks5_send_buf_len;

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

void load_port(int type, char *portname)
{
	static char portlist[512];
	char **av;
	int j, ac;
	port_list *prtlst;

	strlcpy (portlist, portname, 512);
	ac = split_buf(portlist, &av, 0);
	for (j = 0; j < ac; j++) {
		if (atoi(av[j]) == 0) {
			nlog (LOG_WARNING, "Invalid port %s for proxy type %s", av[j], type_of_proxy(type));
			continue;
		}
		if (list_isfull(opsb.ports)) {
			nlog (LOG_WARNING, "Ports list is full.");
			break;
		}
		prtlst = ns_malloc(sizeof(port_list));
		prtlst->type = type;
		prtlst->port = atoi(av[j]);
		prtlst->noopen = 0;
		lnode_create_append (opsb.ports, prtlst);
		dlog (DEBUG1, "Added port %d for protocol %s", prtlst->port, type_of_proxy(type));
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
			load_port(proxy_list[i].type, defaultports[i]);
			DBAStoreConfigStr(proxy_list[i].name, defaultports[i], 512);
			ok = 1;
		} else {
			load_port(proxy_list[i].type, portname);
			ok = 1;
		}
	}
	return ok;				
}

int init_scanengine() {
	struct in_addr addr;
	unsigned long laddr;
	/* set up our send buffers */
	http_send_buf_len = ircsnprintf(http_send_buf, BUFSIZE, "CONNECT %s:%d HTTP/1.0\r\n\r\nquit\r\n\r\n", opsb.targetip, opsb.targetport);
	httppost_send_buf_len = ircsnprintf(httppost_send_buf, BUFSIZE, "POST http://%s:%d/ HTTP/1.0\r\nContent-type: text/plain\r\nContent-length: 5\r\n\r\nquit\r\n\r\n", opsb.targetip, opsb.targetport);
	router_send_buf_len = ircsnprintf(router_send_buf, BUFSIZE, "cisco\r\ntelnet %s %d\r\n", opsb.targetip, opsb.targetport);
	wingate_send_buf_len = ircsnprintf(wingate_send_buf, BUFSIZE, "%s:%d\r\n", opsb.targetip, opsb.targetport);
	
	if (inet_aton(opsb.targetip, &addr) != 0) {
	         laddr = htonl(addr.s_addr);
	} else {
		nlog(LOG_ERROR, "Couldn't Setup connect address for init_scan_engine");
		return NS_FAILURE;
	}
	/* taken from libopm */
	socks4_send_buf_len = ircsnprintf(socks4_send_buf, BUFSIZE, "%c%c%c%c%c%c%c%c%c",  4, 1,
		(((unsigned short) opsb.targetport) >> 8) & 0xFF,
	         (((unsigned short) opsb.targetport) & 0xFF),
	         (char) (laddr >> 24) & 0xFF, (char) (laddr >> 16) & 0xFF,
	         (char) (laddr >> 8) & 0xFF, (char) laddr & 0xFF, 0);
	
	socks5_send_buf_len = ircsnprintf(socks5_send_buf, BUFSIZE, "%c%c%c%c%c%c%c%c%c%c%c%c%c", 5, 1, 0, 5, 1, 0, 1,
                 (char) (laddr >> 24) & 0xFF, (char) (laddr >> 16) & 0xFF,
                 (char) (laddr >> 8) & 0xFF, (char) laddr & 0xFF,
                 (((unsigned short) opsb.targetport) >> 8) & 0xFF,
                 (((unsigned short) opsb.targetport) & 0xFF));	
	
	return NS_SUCCESS;

}         

void start_proxy_scan(scaninfo *scandata) 
{
	int i;
	lnode_t *pn, *cn;
	port_list *pl;
	conninfo *ci;
	char tmpname[512];
	struct timeval tv;

	SET_SEGV_LOCATION();

	if (scandata->reqclient) irc_chanalert (opsb_bot, "Starting proxy scan on %s (%s) by Request of %s", scandata->who, scandata->lookup, scandata->reqclient->name);
	opsb.scanned++;
	tv.tv_sec = opsb.timeout;
	tv.tv_usec = 0;
	scandata->state = DOING_SCAN;
	/* this is so we can timeout scans */
	scandata->started = time(NULL);
	scandata->connections = list_create(-1);
	pn = list_first(opsb.ports);
	while (pn) {
		pl = lnode_get(pn);
		ci = ns_malloc(sizeof(conninfo));
		ci->type = pl->type;
		ci->port = pl->port;
		ci->scandata = scandata;
		/* get the callbacks etc */
		for (i=0; proxy_list[i].type != 0; i++) {
			if (proxy_list[i].type == pl->type) {
				if ((ci->fd = sock_connect(SOCK_STREAM, scandata->ip, ci->port)) == NS_FAILURE) {
					nlog(LOG_WARNING, "start_proxy_scan(): Failed Connect for protocol %s on port %d", type_of_proxy(ci->type), ci->port);
					ns_free(ci);
					pn = list_next(opsb.ports, pn);
					continue;
				}
				/* ok, it worked... lets add it as a standard socket */
				ircsnprintf(tmpname, 512, "%s:%d-%d", type_of_proxy(ci->type), ci->port, ci->fd);
				if (( ci->sock = AddSock(SOCK_STANDARD, tmpname, ci->fd, proxy_read, proxy_list[i].writefunc, EV_WRITE|EV_READ|EV_TIMEOUT|EV_PERSIST, ci, &tv)) == NULL) {
					nlog(LOG_WARNING, "start_proxy_scan(): Failed AddSock for protocol %s on port %d", type_of_proxy(ci->type), ci->port);
					os_sock_close(ci->fd);
					ns_free(ci);
					pn = list_next(opsb.ports, pn);
					continue;
				}				
			}
		}
		lnode_create_append(scandata->connections, ci);
		pn = list_next(opsb.ports, pn);
	}
		

	
}

int http_send (int fd, void *data) {
	conninfo *ci = (conninfo *)data;
	struct timeval tv;
	if (send_to_sock(ci->sock, http_send_buf, http_send_buf_len) != NS_FAILURE) {
		/* our timeout */
		tv.tv_sec = opsb.timeout;
		tv.tv_usec = 0;
		UpdateSock(ci->sock, EV_READ|EV_PERSIST|EV_TIMEOUT, 1, &tv);
	}
	return NS_SUCCESS;
}
int sock4_send(int fd, void *data) {
	conninfo *ci = (conninfo *)data;
	struct timeval tv;
	
	if (send_to_sock(ci->sock, socks4_send_buf, socks4_send_buf_len) != NS_FAILURE) {
		/* our timeout */
		tv.tv_sec = opsb.timeout;
		tv.tv_usec = 0;
		UpdateSock(ci->sock, EV_READ|EV_PERSIST|EV_TIMEOUT, 1, &tv);
	}
	return NS_SUCCESS;
}
int sock5_send(int fd, void *data) {
	conninfo *ci = (conninfo *)data;
	struct timeval tv;
	
	if (send_to_sock(ci->sock, socks5_send_buf, socks5_send_buf_len) != NS_FAILURE) {
		/* our timeout */
		tv.tv_sec = opsb.timeout;
		tv.tv_usec = 0;
		UpdateSock(ci->sock, EV_READ|EV_PERSIST|EV_TIMEOUT, 1, &tv);
	}
	return NS_SUCCESS;
}
int wingate_send(int fd, void *data) {
	conninfo *ci = (conninfo *)data;
	struct timeval tv;
	
	if (send_to_sock(ci->sock, wingate_send_buf, wingate_send_buf_len) != NS_FAILURE) {
		/* our timeout */
		tv.tv_sec = opsb.timeout;
		tv.tv_usec = 0;
		UpdateSock(ci->sock, EV_READ|EV_PERSIST|EV_TIMEOUT, 1, &tv);
	}
	return NS_SUCCESS;
}
int router_send(int fd, void *data) {
	conninfo *ci = (conninfo *)data;
	struct timeval tv;
	
	if (send_to_sock(ci->sock, wingate_send_buf, wingate_send_buf_len) != NS_FAILURE) {
		/* our timeout */
		tv.tv_sec = opsb.timeout;
		tv.tv_usec = 0;
		UpdateSock(ci->sock, EV_READ|EV_PERSIST|EV_TIMEOUT, 1, &tv);
	}
	return NS_SUCCESS;
}
int httppost_send(int fd, void *data) {
	conninfo *ci = (conninfo *)data;
	struct timeval tv;
	if (send_to_sock(ci->sock, httppost_send_buf, httppost_send_buf_len) != NS_FAILURE) {
		/* our timeout */
		tv.tv_sec = opsb.timeout;
		tv.tv_usec = 0;
		UpdateSock(ci->sock, EV_READ|EV_PERSIST|EV_TIMEOUT, 1, &tv);
	}
	return NS_SUCCESS;
}

static int findconn(const void *key1, const void *key2) {
	const conninfo *ci1 = key1;
	const conninfo *ci2 = key2;
	if ((ci1->type == ci2->type) && (ci1->port == ci2->port)) {
		return 0;
	}
	return -1;
}

int proxy_read (void *data, void *recv, size_t size) {
	conninfo *ci = (conninfo *)data;
	scaninfo *si = ci->scandata;
	lnode_t *connode;
	int i;
	/* XXX delete CI */
	switch (size) {
		case -1:	/* connect refused */
		case -2: /* timeout */
			/* XXX Close */
			connode = list_find(si->connections, ci, findconn);
			if (connode) {
				list_delete(si->connections, connode);
				lnode_destroy(connode);
				if (si->reqclient) irc_prefmsg(opsb_bot, si->reqclient, "Connection on %s (%s:%d) for Protocol %s Closed", si->who, si->lookup, ci->port, type_of_proxy(ci->type));
				ns_free(ci);
			}
			if (list_count(si->connections) == 0) {
				if (si->state == DOING_SCAN) si->state = FIN_SCAN;			
				check_scan_free(si);
			}
			return NS_FAILURE;
		default:
			proxy_list[ci->type-1].scanned++;
			for (i = 0; stdmatchstrings[i] != NULL; i++) {
				if (match(stdmatchstrings[i], recv)) {
					proxy_list[ci->type-1].noopen++;
					if (si->state == DOING_SCAN) si->state = GOTOPENPROXY;
					open_proxy(ci);
				}
			}
			break;
	}
	return NS_SUCCESS;
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
	nlog (LOG_CRITICAL, "OPSB: Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, scandata->lookup, type_of_proxy(connection->type), connection->port);
	irc_chanalert (opsb_bot, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, scandata->lookup, type_of_proxy(connection->type), connection->port);
	irc_globops  (opsb_bot, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, scandata->lookup, type_of_proxy(connection->type), connection->port);
	if (scandata->reqclient) irc_prefmsg (opsb_bot, scandata->reqclient, "Banning %s (%s) for Open Proxy - %s(%d)", scandata->who, scandata->lookup, type_of_proxy(connection->type), connection->port);
#if 0
	if (opsb.doakill) 
		/* XXX IP */
		irc_akill (opsb_bot, "", "*", opsb.akilltime, "Open Proxy found on your host. %s(%d)", type_of_proxy(connection->type), connection->port);
#endif
	/* no point continuing the scan if they are found open */
	scandata->state = GOTOPENPROXY;
	/* XXX end scan */
	scandata->doneban = 1;	
}

int opsb_cmd_status (CmdParams* cmdparams) 
{
	lnode_t *node;
	scaninfo *scandata;
	lnode_t *cnode;
	conninfo *ci;
	int i;

	SET_SEGV_LOCATION();
	
	irc_prefmsg (opsb_bot, cmdparams->source, "Proxy Results:");
	irc_prefmsg (opsb_bot, cmdparams->source, "Hosts Scanned: %d Hosts found Open: %d", opsb.scanned, opsb.open);
	irc_prefmsg (opsb_bot, cmdparams->source, "Cache Entries: %d", (int)list_count(cache));
	irc_prefmsg (opsb_bot, cmdparams->source, "Cache Hits: %d", opsb.cachehits);
	irc_prefmsg (opsb_bot, cmdparams->source, "Blacklist Hits: %d", opsb.opmhits);
	for (i = 0; proxy_list[i].type != 0; i++) {
		irc_prefmsg (opsb_bot, cmdparams->source, "Proxy %s Found %d Open %d", proxy_list[i].name, proxy_list[i].scanned, proxy_list[i].noopen);
	}
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
					irc_prefmsg (opsb_bot, cmdparams->source, "    Scanning for Open Proxies");
					break;
			case GOTOPENPROXY:
					irc_prefmsg (opsb_bot, cmdparams->source, "    Contains an Open Proxy");
					break;
			default:
					irc_prefmsg (opsb_bot, cmdparams->source, "    Unknown State (Scan)");
		}
		cnode = list_first(scandata->connections);
		while (cnode) {
			ci = lnode_get(cnode);
			irc_prefmsg(opsb_bot, cmdparams->source, "    Checking for %s Proxy on port %d", type_of_proxy(ci->type), ci->port);
			cnode = list_next(scandata->connections, cnode);
		}
	node = list_next(opsbl, node);
	}
	return 0;
}


