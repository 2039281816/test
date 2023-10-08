
CC="gcc"
AAR=ar cru
CFLAGS= -Wall -g -fPIC -I ./include
LDFLAGS=-lrt -lpthread

SHARED=-shared -o

OBJ	= $(SRC:.c=.o)
HFILE	= $(SRC:.c=.h)
TARGET	= $(SRC:.c=.a)
DSO	= $(SRC:.c=.so)

${OBJ}: ${SRC}
		${CC} ${CFLAGS} -c ${SRC} 

${DSO}: ${SRC}
		${CC} ${CFLAGS} ${SHARED} $@ -c ${SRC}

