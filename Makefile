CC=gcc
CFLAGS= -O2 -march=native
LDFLAGS= -lseccomp
TARGET=sbox
SOURCES=sbox.c
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET) minimize

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)


%.o: %.c
	$(CC) -o $(CFLAGS) -c $< -o $@

minimize:
	strip $(TARGET)

clean:
	rm -rf $(OBJECTS) $(TARGET)
