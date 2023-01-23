
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -g -lcrypto -lwebsockets 
SRC = main.c
OBJ = $(SRC:.c=.o)
EXEC = app.out

chatapp: 
	$(CC) $(CFLAGS) $(SRC) -o $(EXEC)