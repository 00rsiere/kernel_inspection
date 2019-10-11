obj-m += inspector.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cd client && gcc client.c -o inspect -lcapstone

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
