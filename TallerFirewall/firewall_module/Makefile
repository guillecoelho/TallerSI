#
# Makefile to build the kernel module for tsiFirewall
#
CONFIG_MODULE_SIG=n
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
obj-m += tsiFirewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(ROOT_DIR) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean