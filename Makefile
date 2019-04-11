build:

install:
	mkdir -p $(DESTDIR)/$(PREFIX)/bin
	cp zsign.pl $(DESTDIR)/$(PREFIX)/bin/zsign
	cp zverify.pl $(DESTDIR)/$(PREFIX)/bin/zverify
	chmod 755 $(DESTDIR)/$(PREFIX)/bin/zsign $(DESTDIR)/$(PREFIX)/bin/zverify
