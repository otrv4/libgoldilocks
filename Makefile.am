include $(top_srcdir)/variables.am

SUBDIRS = src test pkgconfig
ACLOCAL_AMFLAGS = -I m4

.PHONY: gen_code test_ct todo lib sage sage-test all clean test bench microbench

ci: test mem-check

all-lib:
	$(MAKE) all -f $(top_srcdir)/Makefile.custom

gen-code:
	$(MAKE) gen_code -f $(top_srcdir)/Makefile.custom

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

test:
	$(MAKE) test -f $(top_srcdir)/Makefile.custom

bench:
	$(MAKE) bench -f $(top_srcdir)/Makefile.custom

microbench:
	$(MAKE) microbench -f $(top_srcdir)/Makefile.custom

# NB: you must compile with XCFLAGS=-DNDEBUG or you will get lots of extra warnings due to assert(stuff).
mem-check:
	$(MAKE) mem-check -f $(top_srcdir)/Makefile.custom
