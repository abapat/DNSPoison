#Amit Bapat

CFLAGS = -g -w -Wall -Wno-pointer-sign
LIBS = -lpcap
CC = gcc
OBJS = dnsinject.o

all: dnsinject

dnsinject: $(OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ 

clean:
	rm -f *~ *.o dnsinject
