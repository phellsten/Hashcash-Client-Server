# 
# Makefile for project 1 
#
# Simulation of swapping processes into memory
# and scheduling them on a CPU
#


## CC  = Compiler.
## CFLAGS = Compiler flags.
CC	= gcc
CFLAGS =	-Wall -Wextra -std=gnu99 -g -pthread


## OBJ = Object files.
## SRC = Source files.
## EXE = Executable name.

SRC =		sha256.c server.c
OBJ =		sha256.o server.o
EXE = 		server

## Top level target is executable.
$(EXE):	$(OBJ)
		$(CC) $(CFLAGS) -o $(EXE) $(SRC) -lm


## Clean: Remove object files and core dump files.
clean:
		/bin/rm $(OBJ) 

## Clobber: Performs Clean and removes executable file.

clobber: clean
		/bin/rm $(EXE) 

## Dependencies

sha256.o:sha256.h
server.o:uint256.h sha256.h