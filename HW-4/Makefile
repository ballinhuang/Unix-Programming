CXX	= g++
CFLAGS	= -Wall -g
 
PROGS	= guess autodbg sdb

all: $(PROGS)

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<

autodbg: autodbg.o ptools.o
	$(CXX) -o $@ $^ $(LDFLAGS)

%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o *~ $(PROGS)

