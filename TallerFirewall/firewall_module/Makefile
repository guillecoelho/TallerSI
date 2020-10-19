#
# Makefile to build the kernel module for tsiFirewall
#
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
obj-m += tsiFirewall.o

all:clean
	make -C /lib/modules/$(shell uname -r)/build M=$(ROOT_DIR) modules
clean:
	rm -rf   Module.symvers modules.order
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean