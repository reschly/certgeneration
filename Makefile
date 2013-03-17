CC = gcc
FLAGS = -Wall -Werror
INCLUDE = 
LIBS = -lcrypto


all: makeeccert makeecreq makersacert makersareq

utils.o: utils.c
	$(CC) $(FLAGS) -c utils.c

makeeccert: makeeccert.c utils.o certgeneration.h
	$(CC) $(FLAGS) makeeccert.c utils.o $(INCLUDE) $(LIBS) -o makeeccert
	
makeecreq: makeecreq.c utils.o certgeneration.h
	$(CC) $(FLAGS) makeecreq.c utils.o $(INCLUDE) $(LIBS) -o makeecreq
	
makersacert: makersacert.c utils.o certgeneration.h
	$(CC) $(FLAGS) makersacert.c utils.o $(INCLUDE) $(LIBS) -o makersacert
	
makersareq: makersareq.c utils.o certgeneration.h
	$(CC) $(FLAGS) makersareq.c utils.o $(INCLUDE) $(LIBS) -o makersareq

	
	