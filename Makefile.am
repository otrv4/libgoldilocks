include $(top_srcdir)/variables.am

SUBDIRS = src test pkgconfig
ACLOCAL_AMFLAGS = -I m4

.PHONY: gen_code gen_code_static test_ct todo lib sage sagetest all clean

ci: test mem-check

all-lib:
	$(MAKE) all -f $(top_srcdir)/Makefile.original

gen-code:
	$(MAKE) gen_code -f $(top_srcdir)/Makefile.original

gen-code-static:
	$(MAKE) gen_code_static -f $(top_srcdir)/Makefile.original

test-ct:
	$(MAKE) test_ct -f $(top_srcdir)/Makefile.original

todo:
	$(MAKE) todo -f $(top_srcdir)/Makefile.original

sage:
	$(MAKE) sage -f $(top_srcdir)/Makefile.original

sagetest:
	$(MAKE) sagetest -f $(top_srcdir)/Makefile.original

lib:
	$(MAKE) lib -f $(top_srcdir)/Makefile.original

clean-scan:
	$(MAKE) clean -f $(top_srcdir)/Makefile.original

test: check
	$(top_srcdir)/test/test

bench: check
	$(top_srcdir)/test/test_bench

microbench: check
	$(top_srcdir)/test/test_bench --micro

# NB: you must compile with XCFLAGS=-DNDEBUG or you will get lots of extra warnings due to assert(stuff).
mem-check: check
	valgrind $(top_srcdir)/test/test
