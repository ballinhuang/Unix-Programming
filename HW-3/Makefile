CC	= gcc
CXX	= g++
ASM64	= yasm -f elf64 -DYASM -D__x86_64__ -DPIC
LD = ld

CFLAGS	= -g -Wall -fno-stack-protector -fPIC -nostdlib
LDFLAGS = -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2
 
PROGS	= libmini.so start.o

all: $(PROGS)

%.o: %.asm
	$(ASM64) $< -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $<

libmini.so: libmini64.o libmini.o
	ld -shared -o libmini.so libmini64.o libmini.o

cat1s:
	gcc -c -g -Wall -masm=intel -fno-stack-protector cat1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o cat1s start.o cat1.o -L. -lmini
	LD_LIBRARY_PATH=. ./cat1s
	rm cat1s

clean:
	rm *.o
	rm *.so