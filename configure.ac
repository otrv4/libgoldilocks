dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([libgoldilocks], [0.0.1], [otrv4-dev@autonomia.digital])
AC_CONFIG_SRCDIR([src/include/field.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AM_PROG_AR
LT_INIT

dnl Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET

dnl Checks for libraries.
# FIXME: Replace `main' with a function in `-lc':
#AC_CHECK_LIB([c], [main])
# FIXME: Replace `main' with a function in `-ldecaf':
#AC_CHECK_LIB([decaf], [main])

dnl Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h stdint.h stdlib.h string.h sys/param.h sys/time.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
# TODO: prob do not include bool
# AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

dnl Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memmove memset pow sqrt])

AC_CONFIG_FILES([
                 Makefile
                 src/Makefile
                 test/Makefile
                 pkgconfig/libgoldilocks.pc
                 pkgconfig/Makefile
                 ])
AC_OUTPUT
