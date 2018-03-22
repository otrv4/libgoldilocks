include $(top_srcdir)/variables.am

SUBDIRS = src test pkgconfig
ACLOCAL_AMFLAGS = -I m4

.PHONY: gen_code gen_code_static test_ct todo lib sage sagetest all clean

ci: test mem-check

all-lib:
	$(MAKE) all -f $(top_srcdir)/Makefile.custom

gen-code:
	$(MAKE) gen_code -f $(top_srcdir)/Makefile.custom

gen-code-static:
	$(MAKE) gen_code_static -f $(top_srcdir)/Makefile.custom

test-ct:
	$(MAKE) test_ct -f $(top_srcdir)/Makefile.custom

todo:
	$(MAKE) todo -f $(top_srcdir)/Makefile.custom

sage:
	$(MAKE) sage -f $(top_srcdir)/Makefile.custom

sage-test:
	$(MAKE) sagetest -f $(top_srcdir)/Makefile.custom

lib:
	$(MAKE) lib -f $(top_srcdir)/Makefile.custom

clean-scan:
	$(MAKE) clean -f $(top_srcdir)/Makefile.custom

test: check
	$(top_srcdir)/test/test

bench: check
	$(top_srcdir)/test/test_bench

microbench: check
	$(top_srcdir)/test/test_bench --micro

# NB: you must compile with XCFLAGS=-DNDEBUG or you will get lots of extra warnings due to assert(stuff).
mem-check: check
	valgrind $(top_srcdir)/test/test
