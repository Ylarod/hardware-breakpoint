CROSS:= aarch64-linux-gnu-
KERNEL_DIR:= /home/zwf/x3_src/kernel
CURRENT_PATH:= $(shell pwd)
MODULE_NAME= hw_break

src_dir?= $(shell pwd)
export src_dir


includedir:= -I$(src_dir)/include
EXTRA_CFLAGS+= $(includedir) -g


obj-m:= $(MODULE_NAME).o
$(MODULE_NAME)-objs+= 	hw_breakpoint.o \
						src/hw_breakpointApi.o \
    					src/hw_proc.o \
    					src/hw_breakpointManage.o \
    

all: ko
# 编译驱动
ko:
	make -C $(KERNEL_DIR) M=$(CURRENT_PATH) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" CROSS_COMPILE=${CROSS} ARCH=arm64 modules


clean:
	make -C $(KERNEL_DIR) M=$(CURRENT_PATH) clean