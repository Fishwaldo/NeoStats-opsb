AUTOMAKE_OPTIONS        = foreign
ACLOCAL_AMFLAGS         = -I autotools
AM_MAKEFLAGS            = -s

pkglib_LTLIBRARIES	= opsb.la
opsb_la_SOURCES	= opsb.c  opsb_help.c  proxy.c
noinst_HEADERS		= opsb.h 

opsb_la_LDFLAGS	= -module -avoid-version
#AM_CFLAGS		= @PCRE_CFLAGS@ @CURL_CFLAGS@ 


include $(top_srcdir)/autotools/rules.mk
