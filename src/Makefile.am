include $(top_srcdir)/variables.am

noinst_PROGRAMS = decaf_gen_tables_ed448goldilocks

decaf_gen_tables_ed448goldilocks_SOURCES = utils.c \
					   GENERATED/c/ed448goldilocks/decaf_gen_tables.c \
					   p448/arch_x86_64/f_impl.c \
		       			   p448/f_arithmetic.c \
		       			   GENERATED/c/p448/f_generic.c \
		      			   GENERATED/c/ed448goldilocks/decaf.c \
		      			   GENERATED/c/ed448goldilocks/scalar.c

decaf_gen_tables_ed448goldilocks_CFLAGS = $(AM_CFLAGS) $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(INCFLAGS_448) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
decaf_gen_tables_ed448goldilocks_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS)


GENERATED/c/ed448goldilocks/decaf_tables.c: decaf_gen_tables_ed448goldilocks
	./$< > $@ || (rm $@; exit 1)

noinst_LTLIBRARIES = libdecaf448.la
lib_LTLIBRARIES = libdecaf.la

libdecaf_la_SOURCES = utils.c \
		      shake.c \
		      spongerng.c

libdecaf_la_CFLAGS = $(AM_CFLAGS) $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
libdecaf_la_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS)
libdecaf_la_LIBADD = libdecaf448.la

libdecaf448_la_SOURCES = p448/arch_x86_64/f_impl.c \
		      p448/f_arithmetic.c \
		      GENERATED/c/p448/f_generic.c \
		      GENERATED/c/ed448goldilocks/decaf.c \
		      GENERATED/c/ed448goldilocks/elligator.c \
		      GENERATED/c/ed448goldilocks/scalar.c \
		      GENERATED/c/ed448goldilocks/eddsa.c \
		      GENERATED/c/ed448goldilocks/decaf_tables.c

libdecaf448_la_CFLAGS = $(AM_CFLAGS) $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(INCFLAGS_448) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
libdecaf448_la_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS)

incsubdir = $(includedir)/decaf

incsub_HEADERS = GENERATED/include/decaf/common.h \
		 GENERATED/include/decaf/ed448.h \
		 GENERATED/include/decaf/ed448.hxx \
		 GENERATED/include/decaf/eddsa.hxx \
		 GENERATED/include/decaf/point_448.h \
		 GENERATED/include/decaf/point_448.hxx \
		 GENERATED/include/decaf/secure_buffer.hxx \
		 GENERATED/include/decaf/shake.h \
		 GENERATED/include/decaf/shake.hxx \
		 GENERATED/include/decaf/spongerng.h \
		 GENERATED/include/decaf/spongerng.hxx

include_HEADERS = GENERATED/include/decaf.h \
		  GENERATED/include/decaf.hxx

#pkginclude_HEADERS = GENERATED/include/

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = libdecaf.pc
