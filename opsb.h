/* NetStats - IRC Statistical Services Copyright (c) 1999 Adam Rutter,
** Justin Hammond http://codeworks.kamserve.com
*
** Based from GeoStats 1.1.0 by Johnathan George net@lite.net
*
** NetStats CVS Identification
** $Id$
*/


#ifndef OPSB_H
#define OPSB_H

#include "modconfig.h"
#include "opm_types.h"

typedef struct port_list {
	int type;
	int port;
	int nofound;
	int noopen;
} port_list;


extern char s_opsb[MAXNICK];


/* max scans in the max concurrent scans at any one time */
#define MAX_SCANS 100
/* max queue is the max amount of scans that may be concurrent and queued. */
#define MAX_QUEUE MAX_SCANS * 100
/* max no of exempt entries */
#define MAX_EXEMPTS 20
/* max no of ports to scan */
#define MAX_PORTS 50

struct scanq {
	char who[MAXHOST];
	int state;
	int dnsstate;
	char lookup[MAXHOST];
	char server[MAXHOST];
	struct in_addr ipaddr;
	User *u;
	int doreport;
	time_t started;
	int doneban;
	char connectstring[BUFSIZE];
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
	int doscan;
	int cachehits;
	int opmhits;
	list_t *ports;
} opsb;


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


typedef struct proxy_type {
	int type;
	char name[MAXNICK];
} proxy_type;

	


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
#define FIN_SCAN	0x0080


/* opsb.c */
int findscan(const void *key1, const void *key2);
void do_ban(scaninfo *scandata);
void checkqueue();
void addtocache(unsigned long ipaddr);


/* proxy.c */
void start_proxy_scan(lnode_t *scannode);
void send_status(User *u);
void check_scan_free(scaninfo *scandata);
int init_libopm();
char *type_of_proxy(int type);
int get_proxy_by_name(const char *name);
void add_port(int type, int port);
int load_ports();
 

#endif /* OPSB_H */
