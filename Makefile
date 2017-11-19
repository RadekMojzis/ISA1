all : isamon clear

CC = gcc -std=gnu99

isamon.o: isamon.c
	$(CC) $^ -c

isamon: isamon.o
	$(CC) isamon.o -o $@

clear: 
	rm *.o
	
