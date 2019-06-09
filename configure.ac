# Copyright (c) 2019, Nicola Di Lieto <nicola.dilieto@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

AC_PREREQ(2.69)
AC_INIT([libagentcrypt], [1.0.2])
AC_COPYRIGHT([Copyright (c) 2019 Nicola Di Lieto <nicola.dilieto@gmail.com>])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([build-aux/m4])
AC_CONFIG_SRCDIR([libagentcrypt.c])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.14 foreign subdir-objects])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])
AX_IS_RELEASE([dash-version])
AX_CHECK_ENABLE_DEBUG([yes])

LIBAGENTCRYPT_LIBRARY_VERSION=0:0:0
#                             | | |
#                +------------+ | |
#                |        +-----+ |   
#                |        |       |
#               current:revision:age
#                |        |       |
#                |        |       +- increment if interfaces have been added
#                |        |          set to zero if interfaces have been
#                |        |          removed or changed
#                |        +- increment if source code has changed
#                |           set to zero if current is incremented
#                +- increment if interfaces have been added, removed or changed
AC_SUBST(LIBAGENTCRYPT_LIBRARY_VERSION)

AC_LANG_ASSERT(C)
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = "xno"; then
    AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi
AC_CHECK_FUNCS([getline], [], AC_MSG_ERROR([getline not found]))
AC_CHECK_FUNCS([asprintf], [], AC_MSG_ERROR([asprintf not found]))
AC_CHECK_FUNCS([vfprintf], [], AC_MSG_ERROR([vfprintf not found]))
AC_CHECK_FUNCS([utimensat], [], AC_MSG_ERROR([utimensat not found]))
AC_CHECK_FUNCS([lstat], [], AC_MSG_ERROR([lstat not found]))
AX_CHECK_COMPILE_FLAG([$CFLAGS -Wall], [CFLAGS="$CFLAGS -Wall"])
AX_CHECK_COMPILE_FLAG([$CFLAGS -Wextra], [CFLAGS="$CFLAGS -Wextra"])
AX_CHECK_COMPILE_FLAG([$CFLAGS -pedantic], [CFLAGS="$CFLAGS -pedantic"])

LT_PREREQ([2.4])
LT_INIT
AC_SUBST(LIBTOOL_DEPS)

PKG_CHECK_MODULES([libsodium], [libsodium >= 1.0.16])
LIBS="$LIBS $libsodium_LIBS"
CFLAGS="$CFLAGS $libsodium_CFLAGS"

default_docs_rebuild="no"
AC_ARG_ENABLE(docs-rebuild,
  [AC_HELP_STRING([--enable-docs-rebuild], [rebuild documentation])],
    [],enable_docs_rebuild=$default_docs_rebuild)
AM_CONDITIONAL([ENABLE_DOCS_REBUILD], [test "x$enable_docs_rebuild" = xyes])
AM_COND_IF([ENABLE_DOCS_REBUILD],[
           AC_PATH_PROG([DOXYGEN], [doxygen], [no])
           AS_IF([test "$DOXYGEN" = no], [AC_MSG_ERROR([Could not find doxygen.])])
           AC_PATH_PROG([A2X], a2x, [no])
           AS_IF([test "$A2X" = no], [AC_MSG_ERROR([Could not find a2x.])])
           AC_PATH_PROG([ASCIIDOC], [asciidoc], [no])
           AS_IF([test "$ASCIIDOC" = no], [AC_MSG_ERROR([Could not find asciidoc.])])
           AC_CONFIG_FILES([doxyfile])])

AC_CONFIG_FILES([Makefile libagentcrypt.pc])
AC_OUTPUT

