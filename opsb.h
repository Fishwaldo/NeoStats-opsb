/* NetStats - IRC Statistical Services Copyright (c) 1999 Adam Rutter,
** Justin Hammond http://codeworks.kamserve.com
*
** Based from GeoStats 1.1.0 by Johnathan George net@lite.net
*
** NetStats CVS Identification
** $Id: opsb.h,v 1.4 2002/09/06 06:07:34 fishwaldo Exp $
*/


#ifndef OPSB_H
#define OPSB_H

typedef struct proxy_types {
	char *type;
	int port;
	int (*scan)(int sock);
	int nofound;
	int noopen;
} proxy_types;



char *s_opsb;


/* max scans in the max concurrent scans at any one time */
#define MAX_SCANS 100
/* max queue is the max amount of scans that may be concurrent and queued. */
#define MAX_QUEUE MAX_SCANS * 100
/* max no of exempt entries */
#define MAX_EXEMPTS 20


struct scanq {
	char who[MAXHOST];
	int state;
	int dnsstate;
	char lookup[MAXHOST];
	char server[MAXHOST];
	struct in_addr ipaddr;
	User *u;
	int doreport;
	list_t *socks;
	time_t started;
	int doneban;
};

typedef struct scanq scaninfo;

struct opsb {
	char opmdomain[MAXHOST];
	int init;
	char targethost[MAXHOST];
	char lookforstring[512];
	int targetport;
	int maxbytes;
	int timeout;
	int socks;
	int timedif;
	int open;
	int scanned;
	char scanmsg[512];
	int bantime;
	int confed;
	int cachetime;
} opsb;

struct sockinfo {
	int sock;
	int (*function)(int sock);
	int flags;
	int type;
	int bytes;
	char buf[1024];
};

typedef struct sockinfo socklist;


/* this is the list of items to be queued */
list_t *opsbq;
/* this is the list of currently active scans */
list_t *opsbl;


struct cache_entry {
	unsigned long ip;
	time_t when;
};

typedef struct cache_entry C_entry;


/* this is a list of cached scans */
list_t *cache;

struct exempts {
	char host[MAXHOST];
	int server;
	char who[MAXNICK];
	char reason[MAXHOST];
};

typedef struct exempts exemptinfo;

/* this is the list of exempted hosts/servers */

list_t *exempt;

/* these are some state flags */
#define REPORT_DNS 	0x0001
#define GET_NICK_IP	0x0002
#define DO_OPM_LOOKUP	0x0004
#define DOING_SCAN	0x0008
#define GOTOPENPROXY	0x0010
#define OPMLIST		0x0020
#define	NOOPMLIST	0x0040

/* this is some socklist flags */
#define CONNECTING	0x0001
#define SOCKCONNECTED	0x0002
#define UNCONNECTED	0x0004
#define OPENPROXY	0x0008

/* opsb.c */
int findscan(const void *key1, const void *key2);
void do_ban(scaninfo *scandata);
void checkqueue();
void addtocache(unsigned long ipaddr);


/* proxy.c */
void start_proxy_scan(lnode_t *scannode);
void send_status(User *u);


#endif /* OPSB_H */
