# Copyright (c) 2014-2017 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.


UNAME := $(shell uname)
MACHINE := $(shell uname -m)

# Subdirectories for objects etc.
# Many of them are mapped to build/obj right now, but could be split later.
# The non-build/obj directories are the public interface.
BUILD_OBJ = build/obj
BUILD_C   = src/GENERATED/c
BUILD_H   = src/GENERATED/c
BUILD_PY  = build/obj
BUILD_LIB = build/lib
BUILD_INC = src/GENERATED/include
BUILD_BIN = build/bin
BUILD_IBIN = build/obj/bin

DOXYGEN ?= doxygen

ifeq ($(UNAME),Darwin)
CC = clang
CXX = clang++
else
CC = gcc
CXX = g++
endif
LD = $(CC)
LDXX = $(CXX)
ASM ?= $(CC)

PYTHON ?= python

WARNFLAGS = -pedantic -Wall -Wextra -Werror -Wunreachable-code \
	 -Wmissing-declarations -Wunused-function -Wno-overlength-strings $(EXWARN)

INCFLAGS = -Isrc/include -I$(BUILD_INC) -I$(BUILD_H)
PUB_INCFLAGS = -I$(BUILD_INC)
LANGFLAGS = -std=c99 -fno-strict-aliasing
LANGXXFLAGS = -fno-strict-aliasing
GENFLAGS = -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC
OFLAGS ?= -O2

MACOSX_VERSION_MIN ?= 10.9
ifeq ($(UNAME),Darwin)
GENFLAGS += -mmacosx-version-min=$(MACOSX_VERSION_MIN)
endif

TODAY = $(shell date "+%Y-%m-%d")

ARCHFLAGS ?= -march=native

ifeq ($(CC),clang)
WARNFLAGS_C += -Wgcc-compat
endif

ifeq ($(CXX),clang++)
WARNFLAGS_CXX += -Wgcc-compat
endif

ARCHFLAGS += $(XARCHFLAGS)
CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(WARNFLAGS_C) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
PUB_CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(WARNFLAGS_C) $(PUB_INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
CXXFLAGS = $(LANGXXFLAGS) $(WARNFLAGS) $(WARNFLAGS_CXX) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCXXFLAGS)
LDFLAGS = $(XLDFLAGS)
ASFLAGS = $(ARCHFLAGS) $(XASFLAGS)

SAGE ?= sage
SAGES= $(shell ls test/*.sage)
BUILDPYS= $(SAGES:test/%.sage=$(BUILD_PY)/%.py)

.PHONY: clean all test test_ct bench todo doc lib bat sage sagetest gen_code gen_code_static
.PRECIOUS: $(BUILD_C)/*/%.c $(BUILD_H)/*/%.h  $(BUILD_H)/%.h  $(BUILD_H)/%.hxx $(BUILD_H)/*/%.hxx $(BUILD_IBIN)/%

HEADER_SRCS= $(shell find src/public_include -name "*.h*")
HEADER_PRIVATE_SRCS= $(shell find src/include -name "*.tmpl.h*")
GEN_CODE_0= $(HEADER_SRCS:src/public_include/%=$(BUILD_INC)/%)
GEN_CODE_0+= $(HEADER_PRIVATE_SRCS:src/include/%=$(BUILD_C)/%)
GEN_CODE_1= $(GEN_CODE_0:%.tmpl.h=%.h)
GEN_CODE= $(GEN_CODE_1:%.tmpl.hxx=%.hxx)
HEADERS= Makefile $(shell find src test -name "*.h") $(BUILD_OBJ)/timestamp $(GEN_CODE)

# components needed by the lib
LIBCOMPONENTS = $(BUILD_OBJ)/utils.o $(BUILD_OBJ)/shake.o $(BUILD_OBJ)/sha512.o $(BUILD_OBJ)/spongerng.o
# and per-field components

BENCHCOMPONENTS = $(BUILD_OBJ)/bench.o $(BUILD_OBJ)/shake.o

all: lib $(BUILD_IBIN)/test $(BUILD_BIN)/ristretto $(BUILD_IBIN)/bench $(BUILD_BIN)/shakesum

scan: clean
	scan-build --use-analyzer=`which clang` \
		 -enable-checker deadcode -enable-checker llvm \
		 -enable-checker osx -enable-checker security -enable-checker unix \
		make all

# Internal test programs, which are not part of the final build/bin directory.
$(BUILD_IBIN)/test: $(BUILD_OBJ)/test_decaf.o lib
ifeq ($(UNAME),Darwin)
	$(LDXX) $(LDFLAGS) -o $@ $< -L$(BUILD_LIB) -ldecaf
else
	$(LDXX) $(LDFLAGS) -Wl,-rpath,`pwd`/$(BUILD_LIB) -o $@ $< -L$(BUILD_LIB) -ldecaf
endif

$(BUILD_BIN)/ristretto: $(BUILD_OBJ)/ristretto.o lib
ifeq ($(UNAME),Darwin)
	$(LDXX) $(LDFLAGS) -o $@ $< -L$(BUILD_LIB) -ldecaf
else
	$(LDXX) $(LDFLAGS) -Wl,-rpath,`pwd`/$(BUILD_LIB) -o $@ $< -L$(BUILD_LIB) -ldecaf
endif

# Internal test programs, which are not part of the final build/bin directory.
$(BUILD_IBIN)/test_ct: $(BUILD_OBJ)/test_ct.o lib
ifeq ($(UNAME),Darwin)
	$(LDXX) $(LDFLAGS) -o $@ $< -L$(BUILD_LIB) -ldecaf
else
	$(LDXX) $(LDFLAGS) -Wl,-rpath,`pwd`/$(BUILD_LIB) -o $@ $< -L$(BUILD_LIB) -ldecaf
endif

$(BUILD_IBIN)/bench: $(BUILD_OBJ)/bench_decaf.o lib
ifeq ($(UNAME),Darwin)
	$(LDXX) $(LDFLAGS) -o $@ $< -L$(BUILD_LIB) -ldecaf
else
	$(LDXX) $(LDFLAGS) -Wl,-rpath,`pwd`/$(BUILD_LIB) -o $@ $< -L$(BUILD_LIB) -ldecaf
endif

# Create all the build subdirectories
$(BUILD_OBJ)/timestamp:
	mkdir -p $(BUILD_OBJ) $(BUILD_C) $(BUILD_PY) \
		$(BUILD_LIB) $(BUILD_INC) $(BUILD_BIN) $(BUILD_IBIN) $(BUILD_H) $(BUILD_INC)/decaf \
		$(PER_OBJ_DIRS) $(BUILD_C)/decaf
	touch $@

$(BUILD_INC)/%: src/public_include/% $(BUILD_OBJ)/timestamp
	cp -f $< $@
	
$(BUILD_INC)/%.h: src/public_include/%.tmpl.h src/generator/*
	$(PYTHON) -B src/generator/template.py --per=global --guard=$(@:$(BUILD_INC)/%=%) -o $@ $<
	
$(BUILD_C)/%.h: src/include/%.tmpl.h src/generator/*
	$(PYTHON) -B src/generator/template.py --per=global --guard=$(@:$(BUILD_C)/%=%) -o $@ $<
	
$(BUILD_INC)/%.hxx: src/public_include/%.tmpl.hxx src/generator/*
	$(PYTHON) -B src/generator/template.py --per=global --guard=$(@:$(BUILD_INC)/%=%) -o $@ $<
	
$(BUILD_C)/%.hxx: src/include/%.tmpl.hxx src/generator/*
	$(PYTHON) -B src/generator/template.py --per=global --guard=$(@:$(BUILD_C)/%=%) -o $@ $<

################################################################
# Per-field code: call with field, arch
################################################################
PER_FIELD_C = $(wildcard src/per_field/*.tmpl.c)
PER_FIELD_H = $(wildcard src/per_field/*.tmpl.h*)
define define_field
ARCH_FOR_$(1) ?= $(2)
COMPONENTS_OF_$(1) = $$(BUILD_OBJ)/$(1)/f_impl.o $$(BUILD_OBJ)/$(1)/f_arithmetic.o $$(BUILD_OBJ)/$(1)/f_generic.o
HEADERS_OF_$(1) = $(HEADERS) $$(BUILD_H)/$(1)/f_field.h
LIBCOMPONENTS += $$(COMPONENTS_OF_$(1))
GEN_CODE_FOR_$(1)  = $$(patsubst src/per_field/%,$(BUILD_C)/$(1)/%,$(patsubst %.tmpl.c,%.c,$(PER_FIELD_C)))
GEN_CODE_FOR_$(1) += $$(patsubst src/per_field/%,$(BUILD_H)/$(1)/%,$(patsubst %.tmpl.h,%.h,$(PER_FIELD_H)))
GEN_CODE += $$(GEN_CODE_FOR_$(1))
PER_OBJ_DIRS += $$(BUILD_OBJ)/$(1)

$$(BUILD_C)/$(1)/%.c: src/per_field/%.tmpl.c src/generator/* Makefile
	$(PYTHON) -B src/generator/template.py --per=field --guard=$(1)/`basename $$@` --item=$(1) -o $$@ $$<
	
$$(BUILD_H)/$(1)/%.h: src/per_field/%.tmpl.h src/generator/* Makefile
	$(PYTHON) -B src/generator/template.py --per=field --guard=$(1)/`basename $$@` --item=$(1) -o $$@ $$<

$$(BUILD_OBJ)/$(1)/%.o: $$(BUILD_C)/$(1)/%.c $$(HEADERS_OF_$(1))
	$$(CC) $$(CFLAGS) -I src/$(1) -I src/$(1)/$$(ARCH_FOR_$(1)) -I $(BUILD_H)/$(1) \
	-I $(BUILD_H)/$(1)/$$(ARCH_FOR_$(1)) -I src/include/$$(ARCH_FOR_$(1)) \
	-c -o $$@ $$<

$$(BUILD_OBJ)/$(1)/%.o: src/$(1)/%.c $$(HEADERS_OF_$(1))
	$$(CC) $$(CFLAGS) -I src/$(1) -I src/$(1)/$$(ARCH_FOR_$(1)) -I $(BUILD_H)/$(1) \
	-I $(BUILD_H)/$(1)/$$(ARCH_FOR_$(1)) -I src/include/$$(ARCH_FOR_$(1)) \
	-c -o $$@ $$<

$$(BUILD_OBJ)/$(1)/%.o: src/$(1)/$$(ARCH_FOR_$(1))/%.c $$(HEADERS_OF_$(1))
	$$(CC) $$(CFLAGS) -I src/$(1) -I src/$(1)/$$(ARCH_FOR_$(1)) -I $(BUILD_H)/$(1) \
		-I $(BUILD_H)/$(1)/$$(ARCH_FOR_$(1)) -I src/include/$$(ARCH_FOR_$(1)) \
		-c -o $$@ $$<
endef

################################################################
# Per-field, per-curve code: call with curve, field
################################################################
PER_CURVE_C = $(wildcard src/per_curve/*.tmpl.c)
define define_curve

LIBCOMPONENTS += $$(BUILD_OBJ)/$(1)/decaf.o $$(BUILD_OBJ)/$(1)/elligator.o $$(BUILD_OBJ)/$(1)/scalar.o \
	 $$(BUILD_OBJ)/$(1)/eddsa.o $$(BUILD_OBJ)/$(1)/decaf_tables.o
PER_OBJ_DIRS += $$(BUILD_OBJ)/$(1)
GLOBAL_HEADERS_OF_$(1) = $(BUILD_INC)/decaf/point_$(3).h $(BUILD_INC)/decaf/point_$(3).hxx \
		$(BUILD_INC)/decaf/ed$(3).h $(BUILD_INC)/decaf/ed$(3).hxx
HEADERS_OF_$(1) = $$(HEADERS_OF_$(2)) $$(GLOBAL_HEADERS_OF_$(1))
HEADERS += $$(GLOBAL_HEADERS_OF_$(1))

GEN_CODE_FOR_$(1)  = $$(patsubst src/per_curve/%,$(BUILD_C)/$(1)/%,$(patsubst %.tmpl.c,%.c,$(PER_CURVE_C)))
GEN_CODE_FOR_$(1) += $$(GLOBAL_HEADERS_OF_$(1))
GEN_CODE_P2 += $(BUILD_C)/$(1)/decaf_tables.c
GEN_CODE += $$(GEN_CODE_FOR_$(1))

$$(BUILD_C)/$(1)/%.c: src/per_curve/%.tmpl.c src/generator/* Makefile
	$(PYTHON) -B src/generator/template.py --per=curve --item=$(1) --guard=$(1)/`basename $$@` -o $$@ $$<
	
$$(BUILD_H)/$(1)/%.h: src/per_curve/%.tmpl.h src/generator/* Makefile
	$(PYTHON) -B src/generator/template.py --per=curve --item=$(1) --guard=$(1)/`basename $$@` -o $$@ $$<
	
$$(BUILD_INC)/decaf/point_$(3).%: src/per_curve/point.tmpl.% src/generator/* Makefile
	$(PYTHON) -B src/generator/template.py --per=curve --item=$(1) --guard=$$(@:$(BUILD_INC)/%=%) -o $$@ $$<
	
$$(BUILD_INC)/decaf/ed$(3).%: src/per_curve/eddsa.tmpl.% src/generator/* Makefile
	$(PYTHON) -B src/generator/template.py --per=curve --item=$(1) --guard=$$(@:$(BUILD_INC)/%=%) -o $$@ $$<
	
$$(BUILD_INC)/decaf/elligator_$(3).%: src/per_curve/elligator.tmpl.% src/generator/* Makefile
	$(PYTHON) -B src/generator/template.py --per=curve --item=$(1) --guard=$$(@:$(BUILD_INC)/%=%) -o $$@ $$<
	
$$(BUILD_INC)/decaf/scalar_$(3).%: src/per_curve/scalar.tmpl.% src/generator/* Makefile
	$(PYTHON) -B src/generator/template.py --per=curve --item=$(1) --guard=$$(@:$(BUILD_INC)/%=%) -o $$@ $$<

$$(BUILD_IBIN)/decaf_gen_tables_$(1): $$(BUILD_OBJ)/$(1)/decaf_gen_tables.o \
		$$(BUILD_OBJ)/$(1)/decaf.o $$(BUILD_OBJ)/$(1)/scalar.o $$(BUILD_OBJ)/utils.o \
		$$(COMPONENTS_OF_$(2))
	$$(LD) $$(LDFLAGS) -o $$@ $$^

$$(BUILD_C)/$(1)/decaf_tables.c: $$(BUILD_IBIN)/decaf_gen_tables_$(1)
	./$$< > $$@ || (rm $$@; exit 1)

$$(BUILD_OBJ)/$(1)/%.o: $$(BUILD_C)/$(1)/%.c $$(HEADERS_OF_$(1))
	$$(CC) $$(CFLAGS) -c -o $$@ $$< \
		-I build/obj/curve_$(1)/ -I src/$(2) -I src/$(2)/$$(ARCH_FOR_$(2)) -I src/include/$$(ARCH_FOR_$(2)) \
		-I $(BUILD_H)/$(1) -I $(BUILD_H)/$(2) -I $(BUILD_H)/$(2)/$$(ARCH_FOR_$(2))

$$(BUILD_OBJ)/decaf_gen_tables_$(1).o: src/decaf_gen_tables.c $$(HEADERS_OF_$(1))
	$$(CC) $$(CFLAGS) \
		-I build/obj/curve_$(1) -I src/$(2) -I src/$(2)/$$(ARCH_FOR_$(2)) -I src/include/$$(ARCH_FOR_$(2)) \
		-I $(BUILD_H)/$(1) -I $(BUILD_H)/$(2) -I $(BUILD_H)/$(2)/$$(ARCH_FOR_$(2)) \
		-c -o $$@ $$<
endef

################################################################
# call code above to generate curves and fields
$(eval $(call define_field,p25519,arch_x86_64))
$(eval $(call define_curve,curve25519,p25519,255))
$(eval $(call define_field,p448,arch_x86_64))
$(eval $(call define_curve,ed448goldilocks,p448,448))

# The shakesum utility is in the public bin directory.
$(BUILD_BIN)/shakesum: $(BUILD_OBJ)/shakesum.o $(BUILD_OBJ)/shake.o $(BUILD_OBJ)/sha512.o $(BUILD_OBJ)/utils.o
	$(LD) $(LDFLAGS) -o $@ $^

# The main decaf library, and its symlinks.
lib: $(BUILD_LIB)/libdecaf.so

$(BUILD_LIB)/libdecaf.so: $(BUILD_LIB)/libdecaf.so.1
	ln -sf `basename $^` $@

$(BUILD_LIB)/libdecaf.so.1: $(LIBCOMPONENTS)
	rm -f $@
ifeq ($(UNAME),Darwin)
	libtool -macosx_version_min $(MACOSX_VERSION_MIN) -dynamic -dead_strip -lc -x -o $@ \
		  $(LIBCOMPONENTS)
else ifeq ($(UNAME),SunOS)
	$(LD) $(LDFLAGS) -shared -Wl,-soname,`basename $@` -o $@ $(LIBCOMPONENTS)
	strip --discard-all $@
else
	$(LD) $(LDFLAGS) -shared -Wl,-soname,`basename $@` -Wl,--gc-sections -o $@ $(LIBCOMPONENTS)
	strip --discard-all $@
endif


$(BUILD_OBJ)/%.o: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<
	
$(BUILD_OBJ)/%.o: test/%.c $(HEADERS)
	$(CC) $(PUB_CFLAGS) -c -o $@ $<

$(BUILD_OBJ)/%.o: test/%.cxx $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# The sage test scripts
sage: $(BUILDPYS)

sagetest: sage lib
	$(SAGE) $(BUILD_PY)/test_decaf.sage

$(BUILDPYS): $(SAGES) $(BUILD_OBJ)/timestamp
	cp -f $(SAGES) $(BUILD_PY)/
	$(SAGE) --preparse $(SAGES:test/%.sage=$(BUILD_PY)/%.sage)
	# some sage versions compile to .sage.py
	for f in $(SAGES:test/%.sage=$(BUILD_PY)/%); do \
		 if [ -e $$f.sage.py ]; then \
		 	 mv $$f.sage.py $$f.py; \
		 fi; \
	  done

# The documentation files
$(BUILD_DOC)/timestamp:
	mkdir -p `dirname $@`
	touch $@
#
doc: Doxyfile $(BUILD_OBJ)/timestamp gen_code_static
	$(DOXYGEN) > /dev/null

gen_code_static: $(GEN_CODE)
gen_code: gen_code_static $(GEN_CODE_P2)

# Finds todo items in .h and .c files
TODO_TYPES ?= HACK TODO @todo FIXME BUG XXX PERF FUTURE REMOVE MAGIC UNIFY
TODO_LOCATIONS ?= src/*.c src/include src/p* src/generator test Makefile Doxyfile
todo::
	@(find $(TODO_LOCATIONS) -name '*.h' -or -name '*.c' -or -name '*.cxx' -or -name '*.hxx' -or -name '*.py') | xargs egrep --color=auto -w \
		`echo $(TODO_TYPES) | tr ' ' '|'`
	@echo '============================='
	@(for i in $(TODO_TYPES); do \
	  (find $(TODO_LOCATIONS) -name '*.h' -or -name '*.c' -or -name '*.cxx' -or -name '*.hxx' -or -name '*.py') | xargs egrep -w $$i > /dev/null || continue; \
	  /bin/echo -n $$i'       ' | head -c 10; \
	  (find $(TODO_LOCATIONS) -name '*.h' -or -name '*.c' -or -name '*.cxx' -or -name '*.hxx' -or -name '*.py') | xargs egrep -w $$i| wc -l; \
	done)
	@echo '============================='
	@echo -n 'Total     '
	@(find $(TODO_LOCATIONS) -name '*.h' -or -name '*.c' -or -name '*.cxx' -or -name '*.hxx' -or -name '*.py') | xargs egrep -w \
		`echo $(TODO_TYPES) | tr ' ' '|'` | wc -l

bench: $(BUILD_IBIN)/bench
	./$<

test: $(BUILD_IBIN)/test
	./$<

test_ct: $(BUILD_IBIN)/test_ct
	# NB: you must compile with XCFLAGS=-DNDEBUG or you will get lots of extra warnings due to assert(thing that is always true).
	valgrind ./$<
	
microbench: $(BUILD_IBIN)/bench
	./$< --micro

clean:
	rm -fr build

clean_generated: clean
	rm -fr $(BUILD_C)/* $(BUILD_H)/* $(BUILD_INC)/*
