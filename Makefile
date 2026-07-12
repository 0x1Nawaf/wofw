CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE -Iinclude
LDFLAGS =
NFQ_CFLAGS = $(shell pkg-config --cflags libnetfilter_queue)
NFQ_LIBS   = $(shell pkg-config --libs libnetfilter_queue)

CFLAGS += $(NFQ_CFLAGS)
LDFLAGS += $(NFQ_LIBS)

SRCS = main.c rules.c packet.c match.c nfq.c log.c iptables.c ctl.c
OBJS = $(SRCS:%.c=src/%.o)
TARGET = wofw
DAEMON = wofwd

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DOCDIR  ?= $(PREFIX)/share/doc/wofw
EXAMPLEDIR ?= $(DOCDIR)/examples
SYSCONFDIR ?= /etc/wofw
SYSTEMD_UNIT_DIR ?= /lib/systemd/system

.PHONY: all clean install

all: $(TARGET) $(DAEMON)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(DAEMON): $(TARGET)
	ln -sf $(TARGET) $(DAEMON)

src/%.o: src/%.c include/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -d "$(DESTDIR)$(BINDIR)"
	install -d "$(DESTDIR)$(DOCDIR)"
	install -d "$(DESTDIR)$(EXAMPLEDIR)"
	install -d "$(DESTDIR)$(SYSCONFDIR)"
	install -d "$(DESTDIR)$(SYSTEMD_UNIT_DIR)"
	install -m 0755 $(TARGET) "$(DESTDIR)$(BINDIR)/$(TARGET)"
	ln -sf $(TARGET) "$(DESTDIR)$(BINDIR)/$(DAEMON)"
	install -m 0644 README.md "$(DESTDIR)$(DOCDIR)/"
	install -m 0644 ../docs/DESIGN.md ../docs/PACKAGING.md "$(DESTDIR)$(DOCDIR)/"
	install -m 0644 examples/rules.conf "$(DESTDIR)$(EXAMPLEDIR)/"
	install -m 0644 packaging/wofw.service "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/wofw.service"
	test -f "$(DESTDIR)$(SYSCONFDIR)/rules.conf" || \
		install -m 0644 examples/rules.conf "$(DESTDIR)$(SYSCONFDIR)/rules.conf"

clean:
	rm -f $(OBJS) $(TARGET) $(DAEMON)
