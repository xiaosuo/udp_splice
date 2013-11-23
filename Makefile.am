ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = \
	  src \
	  include \
	  examples

dist_doc_DATA = \
		README.md \
		LICENSE.txt

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = udp_splice.pc
DISTCLEANFILES = udp_splice.pc
EXTRA_DIST = udp_splice.pc.in
