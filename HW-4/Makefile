CXX	= g++
CFLAGS	= -lelf -Wall -g
 
PROGS	= guess autodbg sdb elfdemo

all: $(PROGS)

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<

autodbg: autodbg.o ptools.o
	$(CXX) -o $@ $^ $(CFLAGS)

elfdemo: elfdemo.o elftool.o

sdb: sdb.o ptools.o elftool.o
	$(CXX) -o $@ $^ $(CFLAGS)

%: %.o
	$(CXX) -o $@ $^ $(CFLAGS)

clean:
	rm -f *.o *~ $(PROGS)

