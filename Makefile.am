include $(top_srcdir)/variables.am

SUBDIRS = src test pkgconfig
ACLOCAL_AMFLAGS = -I m4

.PHONY: gen_code
gen_code:
	$(MAKE) gen_code -f $(top_srcdir)/Makefile.original

test: check
	$(top_srcdir)/test/test

bench: check
	$(top_srcdir)/test/test_bench

microbench: check
	$(top_srcdir)/test/test_bench --micro

# NB: you must compile with XCFLAGS=-DNDEBUG or you will get lots of extra warnings due to assert(stuff).
mem-check: check
	valgrind $(top_srcdir)/test/test_ct
