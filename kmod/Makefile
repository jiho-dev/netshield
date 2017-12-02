
COMM_FILES= lkm.c main.c misc.c commands.c log.c frag.c sysctl.c 
COMM_FILES+=options.c session.c smgr.c parse_proto.c
COMM_FILES+=cuckoo.c MurmurHash3.c pmgr.c
COMM_FILES+=khypersplit.c ioctl.c fw_policy.c timer.c tcp_state.c
COMM_FILES+=nat.c interval_tree.c
COMM_FILES+=arp_proxy.c

obj-m=netshield.o
netshield-objs=$(patsubst %.c,/%.o,$(COMM_FILES)) 

KERNEL_SRC="../linux-4.10.17"
PWD:=$(shell pwd)
ARCH=x86_64

#DBG=-DCONFIG_NS_DEBUG -g
#EXTRA_CFLAGS+=-I$(PWD)/include/.

ccflags-y:= -I$(INC_DIRS) $(DBG)

all:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) INC_DIRS=$(PWD)/include modules
	make -C $(KERNEL_SRC) M=$(PWD) INC_DIRS=$(PWD)/include modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f tags

custom:
	ctags -R

