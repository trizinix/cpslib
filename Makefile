CFLAGS=-g -Wall -Wextra -Wfloat-equal -Wundef -Wformat=2 -Winit-self -Wpointer-arith -Wcast-align 
CFLAGS+=-Wstrict-overflow=5 -Wswitch-enum -Wunreachable-code -Wswitch-enum # -fsanitize=address
CFLAGS+=-fno-omit-frame-pointer -std=gnu99
#=-Wstrict-prototypes  -Wwrite-strings  -Wshadow

ifdef COMSPEC
	PLATFORM := "WINDOWS"
else
	PLATFORM := "LINUX"
endif

driver: driver.c pslib_linux.o common.o
	gcc -D${PLATFORM} ${CFLAGS} driver.c pslib_linux.o common.o -lm -o driver

proc_driver: proc_driver.c pslib_linux.o common.o process.o hash.o
	gcc -D${PLATFORM} ${CFLAGS} proc_driver.c hash.o pslib_linux.o common.o process.o -lm -o proc_driver

pslib_linux.o:  pslib_linux.c pslib.h
	gcc -D${PLATFORM}  ${CFLAGS} -c pslib_linux.c -lm -o pslib_linux.o

common.o: common.c common.h
	gcc -D${PLATFORM}  ${CFLAGS}  -O3 -c common.c -lm -o common.o

process.o: process.c process.h
	gcc -D${PLATFORM}  ${CFLAGS} -Wextra -Wno-unused-but-set-parameter -c process.c -lm -o process.o

hash.o: deps/hash/hash.c deps/hash/hash.h deps/hash/khash.h
	gcc -D${PLATFORM}  ${CFLAGS} -c deps/hash/hash.c -lm -o hash.o

clean:
	rm -f *.o a.out driver

check-syntax:
	gcc -Wall -o nul -S ${CHK_SOURCES}

