CC=gcc
CFLAGS= -g
LDFLAGS= 
TARGET=sbox
SOURCES=sbox.c
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)


%.o: %.c
	$(CC) -o $(CFLAGS) -c $< -o $@


clean:
	rm -rf $(OBJECTS) $(TARGET)
