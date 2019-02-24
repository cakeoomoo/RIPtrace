all: RIPtrace

CC := gcc 

RIPtrace: RIPtrace.c
	$(CC) -o RIPtrace RIPtrace.c -Wall
	$(CC) -o hello hello.c -Wall

clean:
	rm kilo

