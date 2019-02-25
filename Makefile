all: RIPtrace

CC := gcc 

RIPtrace: RIPtrace.c
	$(CC) -o RIPtrace RIPtrace.c -Wall

clean:
	rm kilo

