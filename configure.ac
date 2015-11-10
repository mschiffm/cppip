#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Compressed Pcap Packet Indexing Program], [1.5.0],
	[themikeschiffman@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([z], [inflate])
AC_CHECK_LIB([m], [floor])
AC_CHECK_LIB([tabix], [bgzf_open], ,[AC_MSG_ERROR(cannot find tabixtools library you need to install it or tell me where to find it)])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h sys/time.h])
AC_CHECK_HEADERS([bgzf.h], ,[AC_MSG_ERROR(cannot find tabixtools header you need to install it or tell me where to find it)])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([floor gettimeofday memset strdup strerror strtol])


AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
