BINNAME=inspect
LIBNAME=libinspect.so
CC=gcc
CFLAGS+=-O3
SHARED_CFLAGS=--shared -DSHARED_LIB_MODE
REQUIRED_LIBS=capstone


build:
	$(CC) $(CFLAGS) inspect.c -o $(BINNAME) -l $(REQUIRED_LIBS)

shared:
	$(CC) $(CFLAGS) $(SHARED_CFLAGS) inspect.c -o $(LIBNAME) -l $(REQUIRED_LIBS)

clean:
	rm -f *.o && rm -f $(BINNAME) rm -f $(LIBNAME)
