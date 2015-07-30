KERNELDIR=/lib/modules/$(shell uname -r)/build
#ARCH=i386
#KERNELDIR=/usr/src/kernels/3.2.0-49-generic-pae/build

MODULES = ContainerAccessControl.ko
obj-m += ContainerAccessControl.o

all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

install:	
	make -C $(KERNELDIR) M=$(PWD) modules_install

quickInstall:
	cp $(MODULES) /lib/modules/2.6.32-431.23.3.el6.x86_64/extra
