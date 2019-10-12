obj-m += inspector.o
CLIENT_PATH=client
EXTRA_CFLAGS=-I$(PWD)/../include

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
