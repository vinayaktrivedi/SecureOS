KERNEL_PATH ?= ~/Desktop/6thSem/UGP/SecureOS/src/kernel/host/linux-4.20.6

obj-m += vm_module.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
