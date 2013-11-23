AM_CFLAGS = -I${top_srcdir}/include -Wall -Werror
lib_LTLIBRARIES = libudp_splice.la
libudp_splice_la_SOURCES = libudp_splice.c
libudp_splice_la_LIBADD = -lpthread
libudp_splice_la_LDFLAGS = -version-info 0:0:0

# TODO: use autoconf
KDIR ?= /lib/modules/`uname -r`/build

.PHONY: modules modules_install modules_clean

modules:
	$(MAKE) -C $(KDIR) M=${abs_srcdir} $@

modules_install:
	$(MAKE) -C $(KDIR) M=${abs_srcdir} INSTALL_MOD_PATH=${DESTDIR} $@

modules_clean:
	$(MAKE) -C $(KDIR) M=${abs_srcdir} clean

all-local: modules

install-exec-local: modules_install

clean-local: modules_clean

uninstall-local:
	$(RM) ${DESTDIR}/lib/modules/`uname -r`/extra/udp_splice.ko

EXTRA_DIST = \
	     Kbuild \
	     udp_splice.c
