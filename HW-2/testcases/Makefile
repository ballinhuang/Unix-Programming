CC	= gcc
PROGS	= dir file fscanf getline stdio
PRELOAD	= ../fsmon.so

all: $(PROGS)

%: %.c
	$(CC) -o $@ $(CFLAGS) $^

wget:
	LD_PRELOAD=$(PRELOAD) wget -O /dev/null google.com > /dev/null
	
cat:
	LD_PRELOAD=$(PRELOAD) cat /etc/passwd > /dev/null

ls:
	MONITOR_OUTPUT=/tmp/lsdev.log LD_PRELOAD=$(PRELOAD) ls -la /dev > /dev/null

clean:
	rm -f $(PROGS)

testdir:
	 LD_PRELOAD=../fsmon.so ./dir > /dev/null
	
testfile:
	LD_PRELOAD=../fsmon.so ./file > /dev/null

testfscanf:
	LD_PRELOAD=../fsmon.so ./scanf > /dev/null

testgetline:
	LD_PRELOAD=../fsmon.so ./getline > /dev/null