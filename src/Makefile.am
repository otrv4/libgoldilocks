include $(top_srcdir)/variables.am

noinst_PROGRAMS = goldilocks_gen_tables_ed448goldilocks

goldilocks_gen_tables_ed448goldilocks_SOURCES = utils.c \
					   GENERATED/c/ed448goldilocks/goldilocks_gen_tables.c \
					   p448/arch_x86_64/f_impl.c \
		       			   p448/f_arithmetic.c \
		       			   GENERATED/c/p448/f_generic.c \
		      			   GENERATED/c/ed448goldilocks/decaf.c \
		      			   GENERATED/c/ed448goldilocks/scalar.c

goldilocks_gen_tables_ed448goldilocks_CFLAGS = $(AM_CFLAGS) $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(INCFLAGS_448) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
goldilocks_gen_tables_ed448goldilocks_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS)


GENERATED/c/ed448goldilocks/decaf_tables.c: goldilocks_gen_tables_ed448goldilocks
	./$< > $@ || (rm $@; exit 1)

noinst_LTLIBRARIES = libgoldilocks448.la
lib_LTLIBRARIES = libgoldilocks.la

libgoldilocks_la_SOURCES = utils.c \
		      shake.c \
		      spongerng.c

libgoldilocks_la_CFLAGS = $(AM_CFLAGS) $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
libgoldilocks_la_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS)
libgoldilocks_la_LIBADD = libgoldilocks448.la

libgoldilocks448_la_SOURCES = p448/arch_x86_64/f_impl.c \
		      p448/f_arithmetic.c \
		      GENERATED/c/p448/f_generic.c \
		      GENERATED/c/ed448goldilocks/decaf.c \
		      GENERATED/c/ed448goldilocks/elligator.c \
		      GENERATED/c/ed448goldilocks/scalar.c \
		      GENERATED/c/ed448goldilocks/eddsa.c \
		      GENERATED/c/ed448goldilocks/decaf_tables.c

libgoldilocks448_la_CFLAGS = $(AM_CFLAGS) $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(INCFLAGS_448) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
libgoldilocks448_la_LDFLAGS = $(AM_LDFLAGS) $(XLDFLAGS)

incsubdir = $(includedir)/goldilocks

incsub_HEADERS = GENERATED/include/goldilocks/common.h \
		 GENERATED/include/goldilocks/ed448.h \
		 GENERATED/include/goldilocks/ed448.hxx \
		 GENERATED/include/goldilocks/eddsa.hxx \
		 GENERATED/include/goldilocks/point_448.h \
		 GENERATED/include/goldilocks/point_448.hxx \
		 GENERATED/include/goldilocks/secure_buffer.hxx \
		 GENERATED/include/goldilocks/shake.h \
		 GENERATED/include/goldilocks/shake.hxx \
		 GENERATED/include/goldilocks/spongerng.h \
		 GENERATED/include/goldilocks/spongerng.hxx

include_HEADERS = GENERATED/goldilocks/goldilocks.h \
		  GENERATED/include/goldilocks.hxx

#pkginclude_HEADERS = GENERATED/include/

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = libdecaf.pc
