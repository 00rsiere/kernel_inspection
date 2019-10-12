BINNAME=inspect_client
LIBNAME=inspect
CC=gcc
REQUIRED_LIBS=capstone
LIB_DIR=$(PWD)/../lib/
INCLUDE_DIR=$(PWD)/../include
CFLAGS+=-O3 -Wl,-rpath=$(PWD)/../lib/


build:
	$(CC) $(CFLAGS) -I $(INCLUDE_DIR) *.c -o $(BINNAME) -l $(REQUIRED_LIBS) -l $(LIBNAME) -L $(LIB_DIR)

clean:
	rm -f *.o && rm -f $(BINNAME)
