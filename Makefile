# Copyright (c) 2014 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.


UNAME := $(shell uname)
MACHINE := $(shell uname -m)

# Subdirectories for objects etc.
# Many of them are mapped to build/obj right now, but could be split later.
# The non-build/obj directories are the public interface.
BUILD_OBJ = build/obj
BUILD_C   = build/c
BUILD_H   = build/c
BUILD_PY  = build/obj
BUILD_LIB = build/lib
BUILD_INC = build/include
BUILD_BIN = build/bin
BUILD_IBIN = build/obj/bin
BATBASE=ed448goldilocks_decaf_bats_$(TODAY)
BATNAME=build/$(BATBASE)

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

#FIXME ARCHFLAGS
ARCHFLAGS ?= -maes -mavx2 -mbmi2 #TODO

ifeq ($(CC),clang)
WARNFLAGS += -Wgcc-compat
endif

ARCHFLAGS += $(XARCHFLAGS)
CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
PUB_CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(PUB_INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
CXXFLAGS = $(LANGXXFLAGS) $(WARNFLAGS) $(PUB_INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCXXFLAGS)
LDFLAGS = $(XLDFLAGS)
ASFLAGS = $(ARCHFLAGS) $(XASFLAGS)

SAGE ?= sage
SAGES= $(shell ls test/*.sage)
BUILDPYS= $(SAGES:test/%.sage=$(BUILD_PY)/%.py)

.PHONY: clean all test test_ct bench todo doc lib bat sage sagetest gen_headers
.PRECIOUS: $(BUILD_C)/*/%.c $(BUILD_H)/*/%.h $(BUILD_IBIN)/%

HEADER_SRCS= $(shell find src/public_include -name "*.h*")
GEN_HEADERS_0= $(HEADER_SRCS:src/public_include/%=$(BUILD_INC)/%)
GEN_HEADERS_1= $(GEN_HEADERS_0:%.tmpl.h=%.h)
GEN_HEADERS= $(GEN_HEADERS_1:%.tmpl.hxx=%.hxx)
HEADERS= Makefile $(shell find src test -name "*.h") $(BUILD_OBJ)/timestamp $(GEN_HEADERS)

# components needed by the lib
LIBCOMPONENTS = $(BUILD_OBJ)/utils.o $(BUILD_OBJ)/shake.o # and per-field components

BENCHCOMPONENTS = $(BUILD_OBJ)/bench.o $(BUILD_OBJ)/shake.o

all: lib $(BUILD_IBIN)/test $(BUILD_IBIN)/bench $(BUILD_BIN)/shakesum

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
		$(PER_OBJ_DIRS)
	touch $@

gen_headers: $(GEN_HEADERS)

$(BUILD_INC)/%: src/public_include/% $(BUILD_OBJ)/timestamp
	cp -f $< $@
	
$(BUILD_INC)/%.h: src/public_include/%.tmpl.h src/gen_headers/*
	python -B src/gen_headers/template.py --per=global --guard=$(@:$(BUILD_INC)/%=%) -o $@ $<
	
$(BUILD_INC)/%.hxx: src/public_include/%.tmpl.hxx src/gen_headers/*
	python -B src/gen_headers/template.py --per=global --guard=$(@:$(BUILD_INC)/%=%) -o $@ $<

################################################################
# Per-field code: call with field, arch
################################################################
define define_field
ARCH_FOR_$(1) ?= $(2)
COMPONENTS_OF_$(1) = $$(BUILD_OBJ)/$(1)/f_impl.o $$(BUILD_OBJ)/$(1)/f_arithmetic.o $$(BUILD_OBJ)/$(1)/f_generic.o
HEADERS_OF_$(1) = $(HEADERS) $$(BUILD_H)/$(1)/f_field.h
LIBCOMPONENTS += $$(COMPONENTS_OF_$(1))
PER_OBJ_DIRS += $$(BUILD_OBJ)/$(1)

$$(BUILD_C)/$(1)/%.c: src/per_field/%.tmpl.c src/gen_headers/* $(HEADERS)
	python -B src/gen_headers/template.py --per=field --guard=$(1)/`basename $$@` --item=$(1) -o $$@ $$<
	
$$(BUILD_H)/$(1)/%.h: src/per_field/%.tmpl.h src/gen_headers/* $(HEADERS)
	python -B src/gen_headers/template.py --per=field --guard=$(1)/`basename $$@` --item=$(1) -o $$@ $$<

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
define define_curve

LIBCOMPONENTS += $$(BUILD_OBJ)/$(1)/decaf.o $$(BUILD_OBJ)/$(1)/elligator.o $$(BUILD_OBJ)/$(1)/scalar.o \
	 $$(BUILD_OBJ)/$(1)/crypto.o $$(BUILD_OBJ)/$(1)/decaf_tables.o
PER_OBJ_DIRS += $$(BUILD_OBJ)/$(1)
GLOBAL_HEADERS_OF_$(1) = $(BUILD_INC)/decaf/decaf_$(3).h $(BUILD_INC)/decaf/decaf_$(3).hxx \
		$(BUILD_INC)/decaf/crypto_$(3).h $(BUILD_INC)/decaf/crypto_$(3).hxx
HEADERS_OF_$(1) = $$(HEADERS_OF_$(2)) $$(GLOBAL_HEADERS_OF_$(1))
HEADERS += $$(GLOBAL_HEADERS_OF_$(1))

$$(BUILD_C)/$(1)/%.c: src/per_curve/%.tmpl.c src/gen_headers/* $$(HEADERS_OF_$(2))
	python -B src/gen_headers/template.py --per=curve --item=$(1) --guard=$(1)/`basename $$@` -o $$@ $$<
	
$$(BUILD_H)/$(1)/%.h: src/per_curve/%.tmpl.h src/gen_headers/* $$(HEADERS_OF_$(2))
	python -B src/gen_headers/template.py --per=curve --item=$(1) --guard=$(1)/`basename $$@` -o $$@ $$<
	
$$(BUILD_INC)/decaf/decaf_$(3).%: src/per_curve/decaf.tmpl.% src/gen_headers/* $$(HEADERS_OF_$(2))
	python -B src/gen_headers/template.py --per=curve --item=$(1) --guard=$$(@:$(BUILD_INC)/%=%) -o $$@ $$<
	
$$(BUILD_INC)/decaf/elligator_$(3).%: src/per_curve/elligator.tmpl.% src/gen_headers/* $$(HEADERS_OF_$(2))
	python -B src/gen_headers/template.py --per=curve --item=$(1) --guard=$$(@:$(BUILD_INC)/%=%) -o $$@ $$<
	
$$(BUILD_INC)/decaf/scalar_$(3).%: src/per_curve/scalar.tmpl.% src/gen_headers/* $$(HEADERS_OF_$(2))
	python -B src/gen_headers/template.py --per=curve --item=$(1) --guard=$$(@:$(BUILD_INC)/%=%) -o $$@ $$<
	
$$(BUILD_INC)/decaf/crypto_$(3).%: src/per_curve/crypto.tmpl.% src/gen_headers/* $$(HEADERS_OF_$(2))
	python -B src/gen_headers/template.py --per=curve --item=$(1) --guard=$$(@:$(BUILD_INC)/%=%) -o $$@ $$<

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
$(BUILD_BIN)/shakesum: $(BUILD_OBJ)/shakesum.o $(BUILD_OBJ)/shake.o $(BUILD_OBJ)/utils.o
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
doc: Doxyfile $(BUILD_OBJ)/timestamp $(HEADERS)
	doxygen > /dev/null

# # The eBATS benchmarking script
# bat: $(BATNAME)
#
# $(BATNAME): include/* src/* src/*/* test/batarch.map $(BUILD_C)/decaf_tables.c # TODO tables some other way
# 	rm -fr $@
# 	for prim in dh sign; do \
#           targ="$@/crypto_$$prim/ed448goldilocks_decaf"; \
# 	  (while read arch where; do \
# 	    mkdir -p $$targ/`basename $$arch`; \
# 	    cp include/*.h $(BUILD_C)/decaf_tables.c src/decaf.c src/decaf_crypto.c src/shake.c src/include/*.h src/bat/$$prim.c src/p448/$$where/*.c src/p448/$$where/*.h src/p448/*.c src/p448/*.h $$targ/`basename $$arch`; \
# 	    cp src/bat/api_$$prim.h $$targ/`basename $$arch`/api.h; \
# 	    perl -p -i -e 's/SYSNAME/'`basename $(BATNAME)`_`basename $$arch`'/g' $$targ/`basename $$arch`/api.h;  \
# 	    perl -p -i -e 's/__TODAY__/'$(TODAY)'/g' $$targ/`basename $$arch`/api.h;  \
# 	    done \
# 	  ) < test/batarch.map; \
# 	  echo 'Mike Hamburg' > $$targ/designers; \
# 	  echo 'Ed448-Goldilocks Decaf sign and dh' > $$targ/description; \
#         done
# 	(cd $(BATNAME)/.. && tar czf $(BATBASE).tgz $(BATBASE) )
	
# Finds todo items in .h and .c files
TODO_TYPES ?= HACK TODO FIXME BUG XXX PERF FUTURE REMOVE MAGIC UNIFY
TODO_LOCATIONS ?= src test Makefile Doxyfile
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
	valgrind ./$<
	
microbench: $(BUILD_IBIN)/bench
	./$< --micro

clean:
	rm -fr build
