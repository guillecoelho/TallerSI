#
# Makefile to build the configuration program for tsiFirewall
#

#PREFIX is environment variable, but if it is not set, then set default value
ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

CC = gcc
CFLAGS = -Wall
LDFLAGS = 
OBJFILES = firewall_cli.o
TARGET   = tsiFirewall

.PHONY: all clean install

all: clean $(TARGET)
	
$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET)

install: all
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 111 tsiFirewall $(DESTDIR)$(PREFIX)/bin/
