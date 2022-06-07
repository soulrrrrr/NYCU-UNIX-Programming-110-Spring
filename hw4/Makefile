
CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g
LDFLAGS = 

ASM64	= yasm -f elf64 -DYASM -D__x86_64__

PROGS	= hw4
all: $(PROGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<

hw4: hw4.o helper.o
	$(CXX) -o $@ $^ $(LDFLAGS) -lcapstone

%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o *~ $(PROGS)

