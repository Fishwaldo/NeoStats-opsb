/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2004 Adam Rutter, Justin Hammond, Mark Hetherington
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
** NeoStats CVS Identification
** $Id$
*/

#include "neostats.h"
#include "opsb.h"
#include "exempts.h"

/* this is the list of exempted hosts/servers */
list_t *exempt;

int opsb_cmd_exclude (CmdParams* cmdparams) 
{
	char *buf;
	exemptinfo *exempts;
	int i;
	lnode_t *lnode;

	if (!ircstrcasecmp (cmdparams->av[0], "LIST")) {
		lnode = list_first(exempt);
		i = 1;
		irc_prefmsg (opsb_bot, cmdparams->source, "Exception List:");
		while (lnode) {
			exempts = lnode_get(lnode);
			irc_prefmsg (opsb_bot, cmdparams->source, "%d) %s %s Added by %s for %s", i, exempts->host, (exempts->server ? "(Server)" : "(Client)"), exempts->who, exempts->reason);
			++i;
			lnode = list_next(exempt, lnode);
		}
		irc_prefmsg (opsb_bot, cmdparams->source, "End of list.");
		irc_chanalert (opsb_bot, "%s requested Exception List", cmdparams->source->name);
	} else if (!ircstrcasecmp (cmdparams->av[0], "ADD")) {
		if (cmdparams->ac < 6) {
			return NS_ERR_SYNTAX_ERROR;
		}
		if (list_isfull(exempt)) {
			irc_prefmsg (opsb_bot, cmdparams->source, "Error, Exception list is full");
			return 0;
		}
		if (!index(cmdparams->av[1], '.')) {
			irc_prefmsg (opsb_bot, cmdparams->source, "Host field does not contain a vaild host");
			return 0;
		}
		exempts = malloc(sizeof(exemptinfo));
		strlcpy(exempts->host, cmdparams->av[1], MAXHOST);
		if (atoi(cmdparams->av[2]) > 0)
			exempts->server = 1;
		else 
			exempts->server = 0;
		strlcpy(exempts->who, cmdparams->source->name, MAXNICK);
		buf = joinbuf(cmdparams->av, cmdparams->ac, 3);
		strlcpy(exempts->reason, buf, MAXHOST);
		free(buf);
		lnode = lnode_create(exempts);
		list_append(exempt, lnode);
		DBAStore ("Exempt", exempts->host, exempts, sizeof(exemptinfo));
		irc_prefmsg (opsb_bot, cmdparams->source, "Added %s (%s) exception to list", exempts->host, (exempts->server ? "(Server)" : "(Client)"));
		irc_chanalert (opsb_bot, "%s added %s (%s) exception to list", cmdparams->source->name, exempts->host, (exempts->server ? "(Server)" : "(Client)"));
	} else if (!ircstrcasecmp (cmdparams->av[0], "DEL")) {
		if (cmdparams->ac < 1) {
			return NS_ERR_SYNTAX_ERROR;
		}
		if (atoi(cmdparams->av[1]) != 0) {
			lnode = list_first(exempt);
			i = 1;
			while (lnode) {
				if (i == atoi(cmdparams->av[1])) {
					/* delete the entry */
					exempts = lnode_get(lnode);
					DBADelete ("Exempt", exempts->host);
					list_delete(exempt, lnode);
					irc_prefmsg (opsb_bot, cmdparams->source, "Deleted %s %s out of exception list", exempts->host, (exempts->server ? "(Server)" : "(Client)"));
					irc_chanalert (opsb_bot, "%s deleted %s %s out of exception list", cmdparams->source->name, exempts->host, (exempts->server ? "(Server)" : "(Client)"));
					ns_free(exempts);
					return 1;
				}
				++i;
				lnode = list_next(exempt, lnode);
			}		
			/* if we get here, then we can't find the entry */
			irc_prefmsg (opsb_bot, cmdparams->source, "Error, Can't find entry %d. /msg %s exclude list", atoi(cmdparams->av[1]), opsb_bot->name);
			return 0;
		} else {
			irc_prefmsg (opsb_bot, cmdparams->source, "Error, Out of Range");
			return 0;
		}
	} else {
		return NS_ERR_SYNTAX_ERROR;
	}
	return 0;
}

void new_exempt (void *data)
{
	lnode_t *node;
	exemptinfo *exempts;

	exempts = malloc(sizeof(exemptinfo));
	os_memcpy (exempts, data, sizeof(exemptinfo));
	free (data);
	node = lnode_create(exempts);
	list_prepend(exempt, node);			
	dlog (DEBUG2, "Adding %s (%d) Set by %s for %s to Exempt List", exempts->host, exempts->server, exempts->who, exempts->reason);
}

void LoadExempts (void)
{
	exempt = list_create(MAX_EXEMPTS);
	DBAFetchRows ("Exempt", new_exempt);
}

int IsServerExempt (char *nick, char *host)
{
	lnode_t *node;
	exemptinfo *exempts;

	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->server == 1) {
			/* match a server */
			if (match(exempts->host, host)) {
				dlog (DEBUG1, "OPSB: User %s exempt. Matched host entry %s in Exemptions", nick, exempts->host);
				return 1;
			}
		}
		node = list_next(exempt, node);
	}
	return 0;
}

int IsUserExempt (char *nick, char *host)
{
	lnode_t *node;
	exemptinfo *exempts;

	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->server == 1) {
			/* match a server */
			if (match(exempts->host, host)) {
				dlog (DEBUG1, "OPSB: User %s exempt. Matched server entry %s in Exemptions", nick, exempts->host);
				return 1;
			}
		}
		node = list_next(exempt, node);
	}
	return 0;
}

int GetExemptCount (void)
{
	return list_count(exempt);
}