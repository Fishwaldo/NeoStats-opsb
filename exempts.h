/* NetStats - IRC Statistical Services Copyright (c) 1999 Adam Rutter,
** Justin Hammond http://codeworks.kamserve.com
*
** Based from GeoStats 1.1.0 by Johnathan George net@lite.net
*
** NetStats CVS Identification
** $Id$
*/

#ifndef EXEMPTS_H
#define EXEMPTS_H

void LoadExempts (void);
void SaveExempts (exemptinfo *exempts);
int opsb_cmd_exclude (CmdParams* cmdparams);
int IsServerExempt (char *nick, char *host);
int IsUserExempt (char *nick, char *host);
int GetExemptCount (void);

#endif /* EXEMPTS_H */
