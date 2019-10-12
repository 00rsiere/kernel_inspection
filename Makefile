CLIENT_PATH=client
DRIVER_PATH=driver
LIB_PATH=lib

all: inspector_driver inspector_lib inspector_client
	cd $(CLIENT_PATH) && make build

clean: inspector_driver_clean inspector_lib_clean inspector_client_clean

inspector_client:
	cd $(CLIENT_PATH) && make build

inspector_client_clean:
	cd $(CLIENT_PATH) && make clean

inspector_driver:
	cd $(DRIVER_PATH) && make build

inspector_driver_clean:
	cd $(DRIVER_PATH) && make clean

inspector_lib:
	cd $(LIB_PATH) && make shared

inspector_lib_clean:
	cd $(LIB_PATH) && make clean
