#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([cfw++], [1.0], [bin@vip.qq.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/cfw.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_PROG_AR
LT_INIT

# Checks for programs.
AC_PROG_CXX
AC_PROG_CXX_C_O

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([fork time memcpy memset gethostbyname_r setsockopt])

AH_TOP([
#ifndef __CFW_CONFIG_H__
#define __CFW_CONFIG_H__
])
AH_BOTTOM([
#endif /* __CFW_CONFIG_H__ */
])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

