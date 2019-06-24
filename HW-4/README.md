# Homework 4

# Build
```
$ make
g++ -c -lelf -lcapstone -g sdb.cpp
g++ -c -lelf -lcapstone -g ptools.cpp
g++ -c -lelf -lcapstone -g elftool.cpp
g++ -o sdb sdb.o ptools.o elftool.o -lelf -lcapstone -g
```

# Features

## 有完成的指令
- break 
- cont
- delete
- disasm (不支援 loaded 狀態，只支援 running 狀態)
- exit
- get
- getregs
- help
- list
- load
- run
- vmmap
- set
- si
- start

## 未完成
- dump
- disasm (不支援 loaded 狀態)

# 展示 (作業說明的展示 + 其他展示)
### Load a program, show maps, and run the program (hello64)
```
$ ./sdb

sdb> load ./hello64
** program './hello64' loaded. entry point 0x4000b0, vaddr 0x4000b0, offset 0xb0, size 0x23
sdb> vmmap
00000000004000b0-00000000004000d3 r-x b0      ./hello64
sdb> start
** pid 28823
sdb> vmmap
0000000000400000-0000000000401000 r-x 0         hello64
0000000000600000-0000000000601000 rwx 0         hello64
00007ffef4a08000-00007ffef4a29000 rwx 0         [stack]
00007ffef4add000-00007ffef4ae0000 r-- 0         [vvar]
00007ffef4ae0000-00007ffef4ae2000 r-x 0         [vdso]
7fffffffffffffff-7fffffffffffffff r-x 0         [vsyscall]
sdb> get rip
rip = 4194480 (0x4000b0)
sdb> run
** program ./hello64 is already running.
hello, world!
** child process 28823 terminiated normally (code 0)
sdb> exit
bye~

```

### Start a progrm, and show registers
```
$ ./sdb ./hello64

** program './hello64' loaded. entry point 0x4000b0, vaddr 0x4000b0, offset 0xb0, size 0x23
sdb> start
** pid 28873
sdb> getregs
RAX 0                 RBX 0                 RCX 0                 RDX 0
R8  0                 R9  0                 R10 0                 R11 0
R12 0                 R13 0                 R14 0                 R15 0
RDI 0                 RSI 0                 RBP 0                 RSP 7ffeb91a5d30
RIP 4000b0            FLAGS 0000000000000200
sdb> exit
bye~

```

### Start a program, set a break point, check assembly output, and dump memory (hello64)
```
$ ./sdb ./hello64

** program './hello64' loaded. entry point 0x4000b0, vaddr 0x4000b0, offset 0xb0, size 0x23
sdb> disasm 0x4000b0
Not implement in LOADED status.
sdb> b 0x4000c6
sdb> l
  0:  4000c6
sdb> run
** pid 28961
hello, world!
** breakpoint @             4000c6: b8 01 00 00 00                      mov       eax, 1
sdb> set rip 0x4000b0
sdb> cont
hello, world!
** breakpoint @             4000c6: b8 01 00 00 00                      mov       eax, 1
sdb> delete 0
** breakpoint 0 deleted.
sdb> set rip 0x4000b0
sdb> cont
hello, world!
** child process 28961 terminiated normally (code 0)
sdb> exit
bye~

```

### Load a program, disassemble, set break points, run the program, and change the control flow (guess).
```
$ ./sdb ./guess

** program './guess' loaded. entry point 0x820, vaddr 0x820, offset 0x820, size 0x262
sdb> vmmap
0000000000000820-0000000000000a82 r-x 820      ./guess
sdb> disasm 0x985
Not implement in LOADED status.
sdb> start
** pid 29166
sdb> disasm 0x985
         985: 48 8d 3d 08 01 00 00              lea       rdi, qword ptr [rip + 0x108]
         98c: b8 00 00 00 00                    mov       eax, 0
         991: e8 0a fe ff ff                    call      0x55952b7b57a0
         996: 48 8b 15 73 06 20 00              mov       rdx, qword ptr [rip + 0x200673]
         99d: 48 8d 45 d0                       lea       rax, qword ptr [rbp - 0x30]
         9a1: be 10 00 00 00                    mov       esi, 0x10
         9a6: 48 89 c7                          mov       rdi, rax
         9a9: e8 12 fe ff ff                    call      0x55952b7b57c0
         9ae: 48 8d 45 d0                       lea       rax, qword ptr [rbp - 0x30]
         9b2: ba 00 00 00 00                    mov       edx, 0
sdb> disasm
         9b7: be 00 00 00 00                    mov       esi, 0
         9bc: 48 89 c7                          mov       rdi, rax
         9bf: e8 0c fe ff ff                    call      0x55952b7b57d0
         9c4: 8b 15 52 06 20 00                 mov       edx, dword ptr [rip + 0x200652]
         9ca: 89 d2                             mov       edx, edx
         9cc: 48 39 d0                          cmp       rax, rdx
         9cf: 75 0e                             jne       0x55952b7b59df
         9d1: 48 8d 3d ce 00 00 00              lea       rdi, qword ptr [rip + 0xce]
         9d8: e8 93 fd ff ff                    call      0x55952b7b5770
         9dd: eb 0c                             jmp       0x55952b7b59eb
sdb> b 0x9cc
sdb> vmmap
000055952b7b5000-000055952b7b6000 r-x 0         guess
000055952b9b5000-000055952b9b7000 rw- 0         guess
00007f67dec68000-00007f67dec8f000 r-x 0         ld-2.27.so
00007f67dee8f000-00007f67dee91000 rw- 159744    ld-2.27.so
00007ffed7c32000-00007ffed7c53000 rw- 0         [stack]
00007ffed7d71000-00007ffed7d74000 r-- 0         [vvar]
00007ffed7d74000-00007ffed7d76000 r-x 0         [vdso]
7fffffffffffffff-7fffffffffffffff r-x 0         [vsyscall]
sdb> cont
Show me the key: 1234
** breakpoint @       55952b7b59cc: 48 39 d0                            cmp       rax, rdx
sdb> get rax
rax = 1234 (0x4d2)
sdb> get rdx
rdx = 1234 (0x4d2)
sdb> set rax 1234
sdb> cont
Bingo!
** child process 29166 terminiated normally (code 0)
sdb>

```

### multiple breakpoints (hello64)
```
sdb> load ./hello64

** program './hello64' loaded. entry point 0x4000b0, vaddr 0x4000b0, offset 0xb0, size 0x23
sdb> start
** pid 29671
sdb> disasm 0x4000b0
      4000b0: b8 04 00 00 00                    mov       eax, 4
      4000b5: bb 01 00 00 00                    mov       ebx, 1
      4000ba: b9 d4 00 60 00                    mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                    mov       edx, 0xe
      4000c4: cd 80                             int       0x80
      4000c6: b8 01 00 00 00                    mov       eax, 1
      4000cb: bb 00 00 00 00                    mov       ebx, 0
      4000d0: cd 80                             int       0x80
      4000d2: c3                                ret
      4000d3: 00 68 65                          add       byte ptr [rax + 0x65], ch
sdb> b 0x4000b0
sdb> b 0x4000bf
sdb> b 0x4000c6
sdb> l
  0:  4000b0
  1:  4000bf
  2:  4000c6
sdb> c
** breakpoint @             4000b0: b8 04 00 00 00                      mov       eax, 4
sdb> c
** breakpoint @             4000bf: ba 0e 00 00 00                      mov       edx, 0xe
sdb> c
hello, world!
** breakpoint @             4000c6: b8 01 00 00 00                      mov       eax, 1
sdb> set rip 0x4000b0
sdb> c
** breakpoint @             4000b0: b8 04 00 00 00                      mov       eax, 4
sdb> c
** breakpoint @             4000bf: ba 0e 00 00 00                      mov       edx, 0xe
sdb> c
hello, world!
** breakpoint @             4000c6: b8 01 00 00 00                      mov       eax, 1
sdb> c
** child process 29671 terminiated normally (code 0)
sdb> exit
bye~
```

### help
```
$ ./sdb

sdb> help
 - break {instruction-address}: add a break point
 - cont : continue execution
 - delete {break - point - id} : remove a break point
 - disasm addr : disassemble instructions in a file or a memory region
 - dump addr[length] : dump memory content
 - exit : terminate the debugger
 - get reg : get a single value from a register
 - getregs : show registers
 - help : show this message
 - list : list break points
 - load{path / to / a / program} : load a program
 - run : run the program
 - vmmap : show memory layout
 - set reg val : get a single value to a register
 - si : step into instruction
 - start : start the program and stop at the first instruction
sdb>
```

### si (hello64)
```
$ ./sdb

sdb> load ./hello64
** program './hello64' loaded. entry point 0x4000b0, vaddr 0x4000b0, offset 0xb0, size 0x23
sdb> si
Warning: si [running]: Run a single instruction, and step into function calls.
sdb> start
** pid 29224
sdb> si
sdb> si
sdb> si
sdb> si
sdb> si
hello, world!
sdb> si
sdb> si
sdb> si
** child process 29224 terminiated normally (code 0)
```
