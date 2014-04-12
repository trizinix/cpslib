CFLAGS=-g -Wall 

ifdef COMSPEC
	PLATFORM := "WINDOWS"
else
	PLATFORM := "LINUX"
endif

driver: driver.c pslib_linux.o common.o process.o
	gcc -D${PLATFORM} ${CFLAGS} driver.c process.o pslib_linux.o common.o -lm -o driver

pslib_linux.o:  pslib_linux.c pslib.h
	gcc -D${PLATFORM}  ${CFLAGS} -c pslib_linux.c -lm -o pslib_linux.o

common.o: common.c common.h
	gcc -D${PLATFORM}  ${CFLAGS}  -O3 -c common.c -lm -o common.o

process.o: process.c process.h
	gcc -D${PLATFORM}  ${CFLAGS} -Wextra -Wno-unused-but-set-parameter -c process.c -lm -o process.o

clean:
	rm -f *.o a.out driver

check-syntax:
	gcc -Wall -o nul -S ${CHK_SOURCES}

