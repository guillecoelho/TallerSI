#
# Makefile to build the kernel module for tsiFirewall
#
obj-m += tsiFirewall.o
TOPDIR=$(CURDIR)

all:clean
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	rm -rf   Module.symvers modules.order
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean

install: all
	cp tsiFirewall.ko /lib/modules/$(shell uname -r)/
	depmod
	modprobe tsiFirewall