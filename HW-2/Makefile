CC	= g++
PRELOAD	= ./fsmon.so

all:
	$(CC) -fPIC -shared -o fsmon.so LCM.cpp -ldl

clean:
	rm fsmon.so

cat:
	LD_PRELOAD=$(PRELOAD) cat /etc/passwd > /dev/null
 
testall:
	LD_PRELOAD=$(PRELOAD) ./test