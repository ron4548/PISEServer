CC=gcc
CFLAGS=-g -Wall
TARGET=toy_example_async

all: $(TARGET)

$(TARGET):	$(TARGET).c
		$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c
clean:
		$(RM)	$(TARGET)
