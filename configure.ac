
AC_PREREQ([2.63])                                                                               
AC_INIT([mcsak], m4_esyscmd([tr -d '\n' < facsimile/VERSION]))
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-bzip2])
AC_CONFIG_HEADER([src/config.h])

AC_PREFIX_DEFAULT([/usr/local])

AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL

AC_LANG_C
AC_USE_SYSTEM_EXTENSIONS

AC_HEADER_STDC
AC_HEADER_STAT
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h syslog.h unistd.h])

# Checks for libraries.
AC_CHECK_LIB([rt], [clock_gettime])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_STDBOOL
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([clock_gettime getaddrinfo getifaddrs inet_ntoa localtime_r memset socket strdup strerror strtol])

AC_CONFIG_FILES([
  Makefile
  facsimile/mcsak.spec
  ])

AC_OUTPUT

