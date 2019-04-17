CC	= g++
PRELOAD	= ./fsmon.so

all:
	$(CC) -fPIC -shared -o fsmon.so LCM.cpp -ldl

clean:
	rm fsmon.so

cat:
	LD_PRELOAD=$(PRELOAD) cat /etc/passwd > /dev/null
 
testall:
	gcc -o test test.c
	MONITOR_OUTPUT=./lsdev.log LD_PRELOAD=$(PRELOAD) ./test > /dev/null
	rm test
	cat lsdev.log
