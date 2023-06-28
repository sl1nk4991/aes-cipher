PROJECT = aes
SRC = main.c aes.c

CC = gcc
CFLAGS = 

all: $(PROJECT)

$(PROJECT): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(PROJECT)
