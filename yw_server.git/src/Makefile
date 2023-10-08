include rules.mak

SHELL = /bin/sh
	
TARGET = yw_server

SRC	=  yws_main.c yws_init.c yws_tcps.c

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) -lbpa -lbbl -lpthread -lrt -lm -lcrypt
	cp -p $(TARGET) ../bin

clean:
	rm -f *.o $(TARGET)
