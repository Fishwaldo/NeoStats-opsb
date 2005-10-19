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

/* these are some state flags */
#define DOING_SCAN	0x0008
#define GOTOPENPROXY	0x0010
#define FIN_SCAN		0x0080
/* max scans in the max concurrent scans at any one time */
#define MAX_SCANS 100
/* max queue is the max amount of scans that may be concurrent and queued. */
#define MAX_QUEUE ( MAX_SCANS * 100 )
/* max no of ports to scan */
#define MAX_PORTS 50

typedef struct port_list {
	int type;
	int port;
	int numopen;
} port_list;

typedef struct scaninfo{
	char who[MAXHOST];
	int state;
	char lookup[MAXHOST];
	char server[MAXHOST];
	struct in_addr ip;
	Client *reqclient;
	time_t started;
	int doneban;
	list_t *connections;
} scaninfo;

typedef struct opsbcfg {
	char targetip[MAXHOST];
	char openstring[BUFSIZE];
	int targetport;
	int maxbytes;
	int timeout;
	unsigned int socks;
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
} opsbcfg;

extern Bot *opsb_bot;
extern opsbcfg opsb;
/* this is the list of items to be queued */
extern list_t *opsbq;
/* this is the list of currently active scans */
extern list_t *opsbl;
/* this is a list of cached scans */
extern list_t *cache;

/* opsb.c */
int findscan(const void *key1, const void *key2);
void checkqueue();
void addtocache(unsigned long ip);

/* proxy.c */
void start_proxy_scan( scaninfo *scandata );
int opsb_cmd_status( const CmdParams *cmdparams );
int init_scanengine( void );
char *type_of_proxy( int type );
int get_proxy_by_name( const char *name );
int load_ports( void );
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
