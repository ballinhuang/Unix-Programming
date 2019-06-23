CXX	= g++
CFLAGS	= -lelf -lcapstone -Wall -g
 
PROGS	= guess autodbg sdb elfdemo dump2

all: $(PROGS)

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<

autodbg: autodbg.o ptools.o
	$(CXX) -o $@ $^ $(CFLAGS)

elfdemo: elfdemo.o elftool.o
	$(CXX) -o $@ $^ $(CFLAGS)

dump2: dump2.o ptools.o
	$(CXX) -o $@ $^ $(CFLAGS)

sdb: sdb.o ptools.o elftool.o
	$(CXX) -o $@ $^ $(CFLAGS)

guess:
	$(CXX) -c guess.cpp
	$(CXX) -o $@ guess.o -g

%: %.o
	$(CXX) -o $@ $^ $(CFLAGS)

clean:
	rm -f *.o *~ $(PROGS)

