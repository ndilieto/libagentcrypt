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

ACLOCAL_AMFLAGS = -I build-aux/m4

lib_LTLIBRARIES = libagentcrypt.la
libagentcrypt_la_SOURCES = libagentcrypt.c
libagentcrypt_la_LDFLAGS = -version-info $(LIBAGENTCRYPT_LIBRARY_VERSION)

include_HEADERS = libagentcrypt.h

bin_PROGRAMS = agentcrypt
agentcrypt_SOURCES = agentcrypt.c
agentcrypt_LDADD = libagentcrypt.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libagentcrypt.pc

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

dist_html_DATA = docs/agentcrypt.1.html
dist_man1_MANS = man/man1/agentcrypt.1
dist_man3_MANS = man/man3/agc_decrypt.3 man/man3/agc_fdecrypt.3 \
		 man/man3/agc_free.3 man/man3/agc_malloc.3 \
		 man/man3/agc_version.3 man/man3/agc_encrypt.3 \
		 man/man3/agc_fencrypt.3 man/man3/agc_from_b64.3 \
		 man/man3/agc_to_b64.3 man/man3/libagentcrypt.h.3

if ENABLE_DOCS_REBUILD
man/man1/agentcrypt.1: man/man1/agentcrypt.1.txt
	$(A2X) -d manpage -f manpage -a revision=$(VERSION) $<

$(dist_man3_MANS): $(doc_DATA)

SEDSCRIPT = 's/^libagentcrypt.h \\-\ $$/libagentcrypt.h \\-\
	    Symmetric encryption with SSH Agent/'

docs/agentcrypt.1.html: man/man1/agentcrypt.1.txt libagentcrypt.h \
    $(srcdir)/doxyfile
	if test -d docs; then rm -rf docs/*; fi
	$(DOXYGEN) $(srcdir)/doxyfile
	$(SED) -e $(SEDSCRIPT) -i man/man3/libagentcrypt.h.3
	$(ASCIIDOC) -d manpage -b html5 -a revision=$(VERSION) \
	    -o $@ man/man1/agentcrypt.1.txt
	if test -f doxygen_sqlite3.db; then rm -rf doxygen_sqlite3.db; fi
endif ENABLE_DOCS_REBUILD

install-data-local: $(dist_html_DATA)
	$(mkinstalldirs) $(DESTDIR)$(docdir)
	for f in docs/*; do $(INSTALL_DATA) $$f $(DESTDIR)$(docdir); done

uninstall-local:
	rm -rf $(DESTDIR)$(docdir)

EXTRA_DIST = README.md LICENSE man/man1/agentcrypt.1.txt docs

DISTCLEANFILES = $(pkgconfig_DATA)
