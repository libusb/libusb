AUTOMAKE_OPTIONS = dist-bzip2
ACLOCAL_AMFLAGS = -I m4
DISTCLEANFILES = ChangeLog libusb-1.0.pc
EXTRA_DIST = TODO PORTING BUGS
SUBDIRS = libusb doc

if BUILD_EXAMPLES
SUBDIRS += examples
endif

pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA=libusb-1.0.pc

.PHONY: ChangeLog dist-up
ChangeLog:
	git --git-dir $(top_srcdir)/.git log > ChangeLog || touch ChangeLog

dist-hook: ChangeLog

dist-up: dist
	rsync $(distdir).tar.bz2 frs.sourceforge.net:uploads/

