#
# Makefile to build the configuration program for tsiFirewall
#

CC = gcc
CFLAGS = -Wall
LDFLAGS  = 
OBJFILES = firewall_cli.o
TARGET   = firewall_cli

all: $(TARGET)
	
$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET)
