CC=gcc
CFLAGS=-g -Wall
TARGET=smtp_client

all: $(TARGET)

$(TARGET):	*.c
		$(CC) $(CFLAGS) -o $(TARGET) *.c
clean:
		$(RM)	$(TARGET)
