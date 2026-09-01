# Fuzz targets for OSS-Fuzz.
#
# The parent Makefile.am adds this directory to SUBDIRS only if configure was
# given --enable-fuzzers. A fuzz target has to link against a fuzzing engine,
# which a normal build does not have, so the default is off.
#
#   ./configure --enable-fuzzers
#   make
#
# LIB_FUZZING_ENGINE comes from the environment and names the engine to link.

AM_CPPFLAGS = -I$(top_srcdir)/libusb

noinst_PROGRAMS = \
	fuzz_bos_descriptor \
	fuzz_control_setup \
	fuzz_descriptor_parsers

fuzz_descriptor_parsers_SOURCES = fuzz_descriptor_parsers.c
fuzz_descriptor_parsers_LDADD = $(LIB_FUZZING_ENGINE)

fuzz_bos_descriptor_SOURCES = fuzz_bos_descriptor.c
fuzz_bos_descriptor_LDADD = $(top_builddir)/libusb/libusb-1.0.la $(LIB_FUZZING_ENGINE)

fuzz_control_setup_SOURCES = fuzz_control_setup.c
fuzz_control_setup_LDADD = $(top_builddir)/libusb/libusb-1.0.la $(LIB_FUZZING_ENGINE)

# Every target here is C, but a fuzzing engine is a C++ archive, so the C++
# linker has to be used. Naming a C++ source that is never compiled is the
# automake way to select it.
nodist_EXTRA_fuzz_bos_descriptor_SOURCES = dummy.cxx
nodist_EXTRA_fuzz_control_setup_SOURCES = dummy.cxx
nodist_EXTRA_fuzz_descriptor_parsers_SOURCES = dummy.cxx
