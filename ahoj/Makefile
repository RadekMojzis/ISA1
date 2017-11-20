all : ipk-scanner clear

CC = gcc -std=gnu99

ipk-scanner.o: ipk-scanner.c
	$(CC) $^ -c

ipk-scanner: ipk-scanner.o
	$(CC) ipk-scanner.o -o $@

clear: 
	rm *.o
	
