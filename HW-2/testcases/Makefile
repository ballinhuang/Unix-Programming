CC	= gcc
PROGS	= dir file fscanf getline stdio fopen fread fwrite test
PRELOAD	= ../fsmon.so

all: $(PROGS)

%: %.c
	$(CC) -o $@ $(CFLAGS) $^

wget:
	LD_PRELOAD=$(PRELOAD) wget -O /dev/null google.com > /dev/null
	
cat:
	LD_PRELOAD=$(PRELOAD) cat /etc/passwd > /dev/null

ls:
	MONITOR_OUTPUT=./lsdev.log LD_PRELOAD=$(PRELOAD) ls -la /dev > /dev/null

clean:
	rm -f $(PROGS)

testall:
	 LD_PRELOAD=../fsmon.so ./test > /dev/null

testdir:
	 LD_PRELOAD=../fsmon.so ./dir > /dev/null
	
testfile:
	LD_PRELOAD=../fsmon.so ./file > /dev/null

testfscanf:
	LD_PRELOAD=../fsmon.so ./fscanf

testgetline:
	LD_PRELOAD=../fsmon.so ./getline > /dev/null

testfopen:
	LD_PRELOAD=../fsmon.so ./fopen > /dev/null

testfread:
	LD_PRELOAD=../fsmon.so ./fread > /dev/null

testfwrite:
	LD_PRELOAD=../fsmon.so ./fwrite > /dev/null