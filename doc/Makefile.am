EXTRA_DIST = doxygen.cfg.in

docs: doxygen.cfg
	doxygen $^

docs-upload: docs
	ln -s html api-1.0
	scp -r api-1.0 pbatard@web.sourceforge.net:/home/project-web/libusbx/htdocs
	rm -f api-1.0
