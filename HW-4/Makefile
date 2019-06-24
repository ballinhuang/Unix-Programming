CXX	= g++
CFLAGS	= -lelf -lcapstone -Wall -g

PROGS	= sdb

all: $(PROGS)

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<

sdb: sdb.o ptools.o elftool.o
	$(CXX) -o $@ $^ $(CFLAGS)

%: %.o
	$(CXX) -o $@ $^ $(CFLAGS)

clean:
	rm -f *.o *~ $(PROGS)

