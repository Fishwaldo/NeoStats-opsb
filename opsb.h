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
** NetStats CVS Identification
** $Id$
*/

#ifndef OPSB_H
#define OPSB_H

#include MODULECONFIG

typedef struct port_list {
	int type;
	int port;
	int numfound;
	int numopen;
} port_list;

extern Bot *opsb_bot;

/* max scans in the max concurrent scans at any one time */
#define MAX_SCANS 100
/* max queue is the max amount of scans that may be concurrent and queued. */
#define MAX_QUEUE MAX_SCANS * 100
/* max no of ports to scan */
#define MAX_PORTS 50

typedef struct scaninfo{
	char who[MAXHOST];
	int state;
	char lookup[MAXHOST];
	char server[MAXHOST];
	struct in_addr ip;
	Client *reqclient;
	int doreport;
	time_t started;
	int doneban;
	list_t *connections;
} scaninfo;

struct opsb {
	char targetip[MAXHOST];
	char openstring[BUFSIZE];
	int targetport;
	int maxbytes;
	int timeout;
	int socks;
	int open;
	int scanned;
	char scanmsg[BUFSIZE];
	int akilltime;
	int confed;
	int cachetime;
	int cachesize;
	int cachehits;
	int doakill;
	int doreport;
	int verbose;
	int exclusions;
	list_t *ports;
} opsb;

/* this is the list of items to be queued */
list_t *opsbq;
/* this is the list of currently active scans */
list_t *opsbl;

typedef struct cache_entry {
	unsigned long ip;
	time_t when;
} cache_entry;

/* this is a list of cached scans */
list_t *cache;


typedef struct proxy_type {
	int type;
	char name[MAXNICK];
	sockcb writefunc;
	int scanned;
	int numopen;
} proxy_type;

/* these are some state flags */
#define REPORT_DNS 	0x0001
#define DO_DNS_HOST_LOOKUP	0x0002 
#define DOING_SCAN	0x0008
#define GOTOPENPROXY	0x0010
#define OPMLIST		0x0020
#define NOOPMLIST		0x0040
#define FIN_SCAN		0x0080

/* opsb.c */
int findscan(const void *key1, const void *key2);
void checkqueue();
void addtocache(unsigned long ip);


/* proxy.c */
void start_proxy_scan(scaninfo *scandata);
int opsb_cmd_status (CmdParams* cmdparams) ;
void check_scan_free(scaninfo *scandata);
int init_scanengine();
char *type_of_proxy(int type);
int get_proxy_by_name(const char *name);
int load_ports();
void save_ports( void );
 
/* help text */
extern const char *opsb_about[];
extern const char *opsb_help_check[];
extern const char *opsb_help_status[];
extern const char *opsb_help_remove[];
extern const char *opsb_help_add[];
extern const char *opsb_help_del[];
extern const char *opsb_help_list[];

extern const char *opsb_help_set_akill [];
extern const char *opsb_help_set_targetip [];
extern const char *opsb_help_set_targetport [];
extern const char *opsb_help_set_maxbytes [];
extern const char *opsb_help_set_timeout [];
extern const char *opsb_help_set_openstring [];
extern const char *opsb_help_set_scanmsg [];
extern const char *opsb_help_set_akilltime [];
extern const char *opsb_help_set_cachetime [];
extern const char *opsb_help_set_verbose [];
extern const char *opsb_help_set_exclusions[];
extern const char *opsb_help_set_cachesize[];
extern const char *opsb_help_set_doreport[];
#endif /* OPSB_H */
