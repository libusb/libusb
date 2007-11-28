AUTOMAKE_OPTIONS = dist-bzip2
DISTCLEANFILES = ChangeLog fpusb.pc
EXTRA_DIST = TODO
SUBDIRS = libfpusb

if BUILD_EXAMPLES
SUBDIRS += examples
endif

pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA=fpusb.pc

.PHONY: ChangeLog dist-up
ChangeLog:
	git --git-dir $(top_srcdir)/.git log > ChangeLog || touch ChangeLog

dist-hook: ChangeLog

dist-up: dist
	ncftpput upload.sourceforge.net incoming $(distdir).tar.bz2

