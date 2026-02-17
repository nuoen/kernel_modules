ifeq ($(KERNEL_SRC),)
KERNEL_SRC := ../out/android13-5.15/common
# KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
endif

THIS_MAKEFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
M := $(dir $(THIS_MAKEFILE))

ifneq ($(KERNELRELEASE),)
#call from kernel build system
obj-m := hookmodule.o
hookmodule-objs :=main.o ftracehook.o kprobehook.o systemtabhook.o
else

modules modules_install clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" $(@)
endif
