dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([libgoldilocks], [0.0.1], [otr@cypherpunks.ca],[],[https://otr.cypherpunks.ca])
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

dnl Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h stdint.h stdlib.h string.h sys/param.h sys/time.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
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

AX_CFLAGS_GCC_OPTION([-Wall])
AX_CFLAGS_GCC_OPTION([-Wextra])
AX_CFLAGS_GCC_OPTION([-Werror])
AX_CFLAGS_GCC_OPTION([-Wformat])
AX_CFLAGS_GCC_OPTION([-Wno-format-extra-args])
AX_CFLAGS_GCC_OPTION([-Wfatal-errors])
AX_CFLAGS_GCC_OPTION([-Wbad-function-cast])
AX_CFLAGS_GCC_OPTION([-Wdiv-by-zero])
AX_CFLAGS_GCC_OPTION([-Wfloat-equal])
AX_CFLAGS_GCC_OPTION([-Wnested-externs])
AX_CFLAGS_GCC_OPTION([-Wpointer-arith])
AX_CFLAGS_GCC_OPTION([-Wstrict-prototypes])
AX_CFLAGS_GCC_OPTION([-Wlogical-op])
AX_CFLAGS_GCC_OPTION([-Wbad-cast-qual])
AX_CFLAGS_GCC_OPTION([-Wformat-nonliteral])
AX_CFLAGS_GCC_OPTION([-Wbuiltin-memcpy-chk-size])
AX_CFLAGS_GCC_OPTION([-Wfloat-equal])
AX_CFLAGS_GCC_OPTION([-Wshadow])
AX_CFLAGS_GCC_OPTION([-Wpointer-arith])
AX_CFLAGS_GCC_OPTION([-Wmaybe-uninitialized])
AX_CFLAGS_GCC_OPTION([-Wlogicalop])
AX_CFLAGS_GCC_OPTION([-Wno-type-limits])
AX_CFLAGS_GCC_OPTION([-Wnull-dereference])
AX_CFLAGS_GCC_OPTION([-Wwrite-strings])
AX_CFLAGS_GCC_OPTION([-Wswitch-default])
AX_CFLAGS_GCC_OPTION([-Wswitch-enum])
AX_CFLAGS_GCC_OPTION([-Waddress-of-temporary])
AX_CFLAGS_GCC_OPTION([-Warc])
AX_CFLAGS_GCC_OPTION([-Warraybounds])
AX_CFLAGS_GCC_OPTION([-Wasm])
AX_CFLAGS_GCC_OPTION([-Wgcc-compat])
dnl for undefined behavior
AX_CFLAGS_GCC_OPTION([-fcatch-undefined-behavior])
AX_CFLAGS_GCC_OPTION([-fno-delete-null-pointer-checks])
AX_CFLAGS_GCC_OPTION([-fno-strict-overflow])
AX_CFLAGS_GCC_OPTION([-fno-strict-aliasing])

AX_CFLAGS_GCC_OPTION([-Wno-unknown-pragmas])
AC_CONFIG_FILES([
                 Makefile
                 src/Makefile
                 test/Makefile
                 pkgconfig/libgoldilocks.pc
                 pkgconfig/Makefile
                 ])
AC_OUTPUT

echo \
"----------------------------------------------------------------------------
Thank you for configuring libgoldilocks version ${PACKAGE_VERSION}.
Configuration completed in directory '${prefix}'.
----------------------------------------------------------------------------"

echo
echo "Options used to compile and link:"
echo "  CC            = $CC"
echo "  CFLAGS        = $CFLAGS"
echo "  LDFLAGS       = $LDFLAGS"
echo
