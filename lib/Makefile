LIBNAME=libinspect.so
CC=gcc
CFLAGS+=-O3 --shared
REQUIRED_LIBS=capstone
INCLUDE_DIR=../include

shared:
	$(CC) $(CFLAGS) -I $(INCLUDE_DIR) inspect.c -o $(LIBNAME) -l $(REQUIRED_LIBS)

clean:
	rm -f *.o && rm -f $(LIBNAME)
