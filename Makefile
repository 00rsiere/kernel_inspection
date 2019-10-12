obj-m += inspector.o
CLIENT_PATH=client

build: inspector_client
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	cd $(CLIENT_PATH) && make clean

inspector_client:
	cd $(CLIENT_PATH) && make build
