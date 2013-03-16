CC = gcc
FLAGS = -Wall -Werror
INCLUDE = 
LIBS = -lcrypto


all: makeeccert makeecreq

utils.o: utils.c
	$(CC) $(FLAGS) -c utils.c

makeeccert: makeeccert.c utils.o certgeneration.h
	$(CC) $(FLAGS) makeeccert.c utils.o $(INCLUDE) $(LIBS) -o makeeccert
	
makeecreq: makeecreq.c utils.o certgeneration.h
	$(CC) $(FLAGS) makeecreq.c utils.o $(INCLUDE) $(LIBS) -o makeecreq
	
	