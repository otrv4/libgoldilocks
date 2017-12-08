include $(top_srcdir)/variables.am

check_PROGRAMS = test test_bench

test_SOURCES = test_decaf.cxx
test_CXXFLAGS = $(AM_CXXFLAGS) $(LANGXXFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCXXFLAGS) $(LIBDECAF_CXXFLAGS)
test_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS) $(LIBDECAF_LIBS)
test_LDADD = $(top_srcdir)/src/libdecaf.la

# This is broken
#test_ct_SOURCES = test_ct.cxx
#test_ct_CXXFLAGS = $(AM_CXXFLAGS) $(LANGXXFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCXXFLAGS) $(LIBDECAF_CXXFLAGS)
#test_ct_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS) $(LIBDECAF_LIBS)
#test_ct_LDADD = $(top_srcdir)/src/libdecaf.la

test_bench_SOURCES = bench_decaf.cxx
test_bench_CXXFLAGS = $(AM_CXXFLAGS) $(LANGXXFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCXXFLAGS) $(LIBDECAF_CXXFLAGS)
test_bench_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS) $(LIBDECAF_LIBS)
test_bench_LDADD = $(top_srcdir)/src/libdecaf.la
