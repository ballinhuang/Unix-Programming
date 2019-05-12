CC	= gcc
CXX	= g++
ASM64	= yasm -f elf64 -DYASM -D__x86_64__ -DPIC
LD = ld

CFLAGS	= -g -Wall -fno-stack-protector -fPIC -nostdlib
TESTCFLAGS = -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI
LDFLAGS = -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2

PROGS	= libmini.so start.o

all: $(PROGS)

%.o: %.asm
	$(ASM64) $< -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $<

libmini.so: libmini64.o libmini.o
	$(LD) -shared -o libmini.so libmini64.o libmini.o

cat1: cat1.c
	$(CC) -c $(TESTCFLAGS) $<
	$(LD) $(LDFLAGS) -o $@ start.o $@.o -L. -L.. -lmini
	LD_LIBRARY_PATH=. ./$@
	rm $@

clean:
	rm *.o
	rm *.so