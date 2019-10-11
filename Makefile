obj-m += inspector.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cd client && gcc inspect.c -o inspect -lcapstone

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	cd client && rm -f *.o && rm -f inspect
