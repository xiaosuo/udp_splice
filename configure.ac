#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([udp_splice], [1.0.0], [xiaosuo@gmail.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/udp_splice.c])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_INIT

# Checks for libraries.
AC_ARG_WITH([kbuild],
		AS_HELP_STRING([--with-kbuild=PATH], [PATH to kernel build directory [default="/lib/modules/$(uname -r)/build"]])
AS_HELP_STRING([--without-kbuild], [Build only library]),
		[kbuilddir="$withval"],
		[kbuilddir="/lib/modules/$(uname -r)/build"])
if test "$kbuilddir" = no; then
	kbuilddir="";
fi
AC_SUBST(kbuilddir)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa memset socket])

AC_CONFIG_FILES([Makefile
		 udp_splice.pc
                 include/Makefile
                 src/Makefile
		 examples/Makefile])
AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION
	PACKAGE_TARNAME:		${PACKAGE_TARNAME}
	prefix:				${prefix}
	exec_prefix:			${exec_prefix}
	bindir:				${bindir}
	sysconfdir:			${sysconfdir}
	libdir:				${libdir}
	datarootdir:			${datarootdir}
	docdir:				${docdir}
	includedir:			${includedir}
	kbuilddir:			${kbuilddir}

	CC:				${CC}
	CFLAGS:				${CFLAGS}
	CPPFLAGS:			${CPPFLAGS}
	LDFLAGS:			${LDFLAGS}
])
