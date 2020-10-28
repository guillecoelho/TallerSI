#
# Makefile to build the program tsiFirewall (Module and CLI)
#

all:
	+$(MAKE) -C firewall_cli $(MAKECMDGOALS)
	+$(MAKE) -C firewall_module $(MAKECMDGOALS)

clean:
	+$(MAKE) -C firewall_cli $(MAKECMDGOALS)
	+$(MAKE) -C firewall_module $(MAKECMDGOALS)

cli_clean:
	cd firewall_cli && $(MAKE) clean

cli_all:
	cd firewall_cli && $(MAKE) all

cli_install:
	cd firewall_cli && $(MAKE) install

module_clean:
	cd firewall_module && $(MAKE) clean

module_all:
	cd firewall_module && $(MAKE) all

module_install:
	cd firewall_module && $(MAKE) install