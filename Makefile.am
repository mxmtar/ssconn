
ACLOCAL_AMFLAGS = -I m4 --install

dist_sysconf_DATA = ssconn.conf

dist_bin_SCRIPTS = ssconnctl

bin_PROGRAMS = ssconn

ssconn_CFLAGS = $(AM_CFLAGS) -Wall
ssconn_LDFLAGS = $(AM_LDFLAGS) -lrt

ssconn_SOURCES = \
		ssconn.c

noinst_HEADERS = \
		ss_ctrl_msg.h \
		ss_data_msg.h \
		ss_status.h \
		x_sllist.h \
		x_timer.h \
		polygator-tools.h

CLEANFILES = *~

EXTRA_DIST = ssconn.init
