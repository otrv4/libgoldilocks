# Copyright (c) 2014 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.


UNAME := $(shell uname)
MACHINE := $(shell uname -m)

# Subdirectories for objects etc.
# Many of them are mapped to build/obj right now, but could be split later.
# The non-build/obj directories are the public interface.
BUILD_ASM = build/obj
BUILD_OBJ = build/obj
BUILD_C   = build/obj
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

DECAF ?= decaf_fast

ifneq (,$(findstring x86_64,$(MACHINE)))
ARCH ?= arch_x86_64
else
# no i386 port yet
ARCH ?= arch_ref32
endif

FIELD ?= p25519

WARNFLAGS = -pedantic -Wall -Wextra -Werror -Wunreachable-code \
	 -Wmissing-declarations -Wunused-function -Wno-overlength-strings $(EXWARN)

INCFLAGS = -Isrc/include -Isrc/public_include -Isrc/$(FIELD) -Isrc/$(FIELD)/$(ARCH)
LANGFLAGS = -std=c99 -fno-strict-aliasing
LANGXXFLAGS = -fno-strict-aliasing
GENFLAGS = -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC
OFLAGS ?= -O2

TODAY = $(shell date "+%Y-%m-%d")

ifneq (,$(findstring arm,$(MACHINE)))
ifneq (,$(findstring neon,$(ARCH)))
ARCHFLAGS += -mfpu=neon
else
ARCHFLAGS += -mfpu=vfpv3-d16
endif
ARCHFLAGS += -mcpu=cortex-a8 # FIXME
GENFLAGS += -DN_TESTS_BASE=1000 # sooooo sloooooow
else
ARCHFLAGS += -maes -mavx2 -mbmi2 #TODO
endif

ifeq ($(CC),clang)
WARNFLAGS += -Wgcc-compat
endif

ARCHFLAGS += $(XARCHFLAGS)
CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
CXXFLAGS = $(LANGXXFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCXXFLAGS) 
LDFLAGS = $(XLDFLAGS)
ASFLAGS = $(ARCHFLAGS) $(XASFLAGS)

SAGE ?= sage
SAGES= $(shell ls test/*.sage)
BUILDPYS= $(SAGES:test/%.sage=$(BUILD_PY)/%.py)

.PHONY: clean all test bench todo doc lib bat sage sagetest
.PRECIOUS: $(BUILD_ASM)/%.s

HEADERS= Makefile $(shell find src test -name "*.h") $(shell find . -name "*.hxx") $(BUILD_OBJ)/timestamp

DECAFCOMPONENTS= $(BUILD_OBJ)/$(DECAF).o $(BUILD_OBJ)/shake.o $(BUILD_OBJ)/decaf_crypto.o \
	$(BUILD_OBJ)/$(FIELD).o $(BUILD_OBJ)/f_arithmetic.o $(BUILD_OBJ)/utils.o
ifeq ($(DECAF),decaf_fast)
DECAFCOMPONENTS += $(BUILD_OBJ)/decaf_tables.o
endif

BENCHCOMPONENTS = $(BUILD_OBJ)/bench.o $(BUILD_OBJ)/shake.o

all: lib $(BUILD_IBIN)/test $(BUILD_IBIN)/bench $(BUILD_BIN)/shakesum

scan: clean
	scan-build --use-analyzer=`which clang` \
		 -enable-checker deadcode -enable-checker llvm \
		 -enable-checker osx -enable-checker security -enable-checker unix \
		make all
		
# The shakesum utility is in the public bin directory.
$(BUILD_BIN)/shakesum: $(BUILD_OBJ)/shakesum.o $(BUILD_OBJ)/shake.o $(BUILD_OBJ)/utils.o
	$(LD) $(LDFLAGS) -o $@ $^

# The main decaf library, and its symlinks.
lib: $(BUILD_LIB)/libdecaf.so

$(BUILD_LIB)/libdecaf.so: $(BUILD_LIB)/libdecaf.so.1
	ln -sf `basename $^` $@

$(BUILD_LIB)/libdecaf.so.1: $(DECAFCOMPONENTS)
	rm -f $@
ifeq ($(UNAME),Darwin)
	libtool -macosx_version_min 10.6 -dynamic -dead_strip -lc -x -o $@ \
		  $(DECAFCOMPONENTS)
else
	$(LD) $(LDFLAGS) -shared -Wl,-soname,`basename $@` -Wl,--gc-sections -o $@ $(DECAFCOMPONENTS)
	strip --discard-all $@
endif

# Internal test programs, which are not part of the final build/bin directory.
$(BUILD_IBIN)/test: $(BUILD_OBJ)/test_decaf.o lib
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
	mkdir -p $(BUILD_ASM) $(BUILD_OBJ) $(BUILD_C) $(BUILD_PY) \
		$(BUILD_LIB) $(BUILD_INC) $(BUILD_BIN) $(BUILD_IBIN) $(BUILD_INC)/decaf
	touch $@

$(BUILD_OBJ)/%.o: $(BUILD_ASM)/%.s
	$(ASM) $(ASFLAGS) -c -o $@ $<

$(BUILD_IBIN)/decaf_gen_tables: $(BUILD_OBJ)/decaf_gen_tables.o \
		$(BUILD_OBJ)/$(DECAF).o $(BUILD_OBJ)/$(FIELD).o $(BUILD_OBJ)/f_arithmetic.o $(BUILD_OBJ)/utils.o
	$(LD) $(LDFLAGS) -o $@ $^
	
$(BUILD_C)/decaf_tables.c: $(BUILD_IBIN)/decaf_gen_tables
	./$< > $@
	
$(BUILD_ASM)/decaf_tables.s: $(BUILD_C)/decaf_tables.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<
	
$(BUILD_ASM)/%.s: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<
	
$(BUILD_ASM)/%.s: src/%.cxx $(HEADERS)
	$(CXX) $(CXXFLAGS) -S -c -o $@ $<

$(BUILD_ASM)/%.s: test/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

$(BUILD_ASM)/%.s: test/%.cxx $(HEADERS)
	$(CXX) $(CXXFLAGS) -S -c -o $@ $<

$(BUILD_ASM)/%.s: src/$(FIELD)/$(ARCH)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

$(BUILD_ASM)/%.s: src/$(FIELD)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

# The sage test scripts
sage: $(BUILDPYS)

sagetest: sage lib
	LD_LIBRARY_PATH=$(BUILD_LIB) sage $(BUILD_PY)/test_decaf.sage

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

doc: Doxyfile $(BUILD_OBJ)/timestamp $(HEADERS) src/*.c src/$(FIELD)/$(ARCH)/*.c src/$(FIELD)/$(ARCH)/*.h
	doxygen > /dev/null

# The eBATS benchmarking script
bat: $(BATNAME)

$(BATNAME): include/* src/* src/*/* test/batarch.map $(BUILD_C)/decaf_tables.c # TODO tables some other way
	rm -fr $@
	for prim in dh sign; do \
          targ="$@/crypto_$$prim/ed448goldilocks_decaf"; \
	  (while read arch where; do \
	    mkdir -p $$targ/`basename $$arch`; \
	    cp include/*.h $(BUILD_C)/decaf_tables.c src/decaf_fast.c src/decaf_crypto.c src/shake.c src/include/*.h src/bat/$$prim.c src/p448/$$where/*.c src/p448/$$where/*.h src/p448/*.c src/p448/*.h $$targ/`basename $$arch`; \
	    cp src/bat/api_$$prim.h $$targ/`basename $$arch`/api.h; \
	    perl -p -i -e 's/SYSNAME/'`basename $(BATNAME)`_`basename $$arch`'/g' $$targ/`basename $$arch`/api.h;  \
	    perl -p -i -e 's/__TODAY__/'$(TODAY)'/g' $$targ/`basename $$arch`/api.h;  \
	    done \
	  ) < test/batarch.map; \
	  echo 'Mike Hamburg' > $$targ/designers; \
	  echo 'Ed448-Goldilocks Decaf sign and dh' > $$targ/description; \
        done
	(cd $(BATNAME)/.. && tar czf $(BATBASE).tgz $(BATBASE) )
	
# Finds todo items in .h and .c files
TODO_TYPES ?= HACK TODO FIXME BUG XXX PERF FUTURE REMOVE MAGIC
todo::
	@(find * -name '*.h' -or -name '*.c' -or -name '*.cxx' -or -name '*.hxx') | xargs egrep --color=auto -w \
		`echo $(TODO_TYPES) | tr ' ' '|'`
	@echo '============================='
	@(for i in $(TODO_TYPES); do \
	  (find * -name '*.h' -or -name '*.c' -or -name '*.cxx' -or -name '*.hxx') | xargs egrep -w $$i > /dev/null || continue; \
	  /bin/echo -n $$i'       ' | head -c 10; \
	  (find * -name '*.h' -or -name '*.c' -or -name '*.cxx' -or -name '*.hxx') | xargs egrep -w $$i| wc -l; \
	done)
	@echo '============================='
	@echo -n 'Total     '
	@(find * -name '*.h' -or -name '*.c' -or -name '*.cxx' -or -name '*.hxx') | xargs egrep -w \
		`echo $(TODO_TYPES) | tr ' ' '|'` | wc -l

bench: $(BUILD_IBIN)/bench
	./$<

test: $(BUILD_IBIN)/test
	./$<
	
microbench: $(BUILD_IBIN)/bench
	./$< --micro

clean:
	rm -fr build $(BATNAME)
