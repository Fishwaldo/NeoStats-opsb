AUTOMAKE_OPTIONS        = foreign
ACLOCAL_AMFLAGS         = -I autotools
AM_MAKEFLAGS            = -s

pkglib_LTLIBRARIES	= opsb.la
opsb_la_SOURCES	= opsb.c  opsb_help.c  proxy.c
noinst_HEADERS		= opsb.h 

opsb_la_LDFLAGS	= -module -avoid-version


EXTRA_DIST              	= autotools/ccdv.c autotools/shtool RELNOTES
dist_doc_DATA		= README.opsb README.opsb.html

include $(top_srcdir)/autotools/rules.mk
