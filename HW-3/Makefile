CC	= gcc
CXX	= g++
ASM64	= yasm -f elf64 -DYASM -D__x86_64__ -DPIC
LD = ld

CFLAGS	= -g -Wall -fno-stack-protector -fPIC -nostdlib
TESTCFLAGS = -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI
LDFLAGS = -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2

PROGS	= libmini.so start.o
TESTS = alarm1 alarm2 alarm3 jmp1

all: $(PROGS) 

%.o: %.asm
	$(ASM64) $< -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $<

libmini.so: libmini64.o libmini.o
	$(LD) -shared -o libmini.so libmini64.o libmini.o

alarm1: alarm1.c
	$(CC) -c $(TESTCFLAGS) $<
	$(LD) $(LDFLAGS) -o $@ start.o $@.o -L. -L.. -lmini
	rm $@.o

alarm2: alarm2.c
	$(CC) -c $(TESTCFLAGS) $<
	$(LD) $(LDFLAGS) -o $@ start.o $@.o -L. -L.. -lmini
	rm $@.o

alarm3: alarm3.c
	$(CC) -c $(TESTCFLAGS) $<
	$(LD) $(LDFLAGS) -o $@ start.o $@.o -L. -L.. -lmini
	rm $@.o

jmp1: jmp1.c
	$(CC) -c $(TESTCFLAGS) $<
	$(LD) $(LDFLAGS) -o $@ start.o $@.o -L. -L.. -lmini
	rm $@.o

clean:
	rm -f $(TESTS)
	rm -f *.o
	rm -f *.so