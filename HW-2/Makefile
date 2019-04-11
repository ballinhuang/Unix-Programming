CC	= g++
PRELOAD	= ./fsmon.so

all:
	$(CC) -fPIC -shared -o fsmon.so LCM.cpp -ldl

clean:
	rm fsmon.so

cat:
	LD_PRELOAD=$(PRELOAD) cat /etc/passwd > /dev/null

testone:
	MONITOR_OUTPUT=fsmon.log LD_PRELOAD=$(PRELOAD) head -n 1000 /etc/services > /dev/null