#include <assert.h>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <iostream>
#include <cstring>

#include "elftool.h"
#include "ptools.h"

using namespace std;

#define NOTLOADED 0
#define LOADED 1
#define RUNNING 2
int status = 0;

string programName = "";
pid_t child;
int wait_status;
long long entry, offset, size;

map<string, string> helpmap = {
    {"break", "break or b [loaded and running]: Setup a break point. If a program is loaded but is not running, the address should be within the range specified by the text segment in the ELF file. When a break point is hit, you have to output a message and indicate the corresponding address and instruction."},
    {"cont", "cont or c [running]: continue the execution when a running program is stopped (suspended)."},
    {"disasm", "disasm or d [loaded and running]: Disassemble instructions in a file or a memory region. The address should be within the range specified by the text segment in the ELF file. You only have to dump 10 instructions for each command. If disasm command is executed without an address, it should disassemble the codes right after the previously disassembled codes. See the demonstration section for the sample output format."},
    {"dump", "dump or x [running]: Dump memory content. You only have to dump 80 bytes from a given address. The output contains the addresses, the hex values, and printable ascii characters. If dump command is executed without an address, it should dump the region right after the previous dump."},
    {"get", "get or g [running]: Get the value of a register. Register names are all in lowercase."},
    {"getregs", "getregs [running]: Get the value of all registers."},
    {"load", "load [not loaded]: Load a program into the debugger. When a program is loaded, you have to print out the entry point, the address, the offset, and the size for the text segment."},
    {"run", "run or r [loaded and running]: Run the program. If the program is already running, show a warning message and continue the execution."},
    {"vmmap", "vmmap or m [loaded and running]: Show memory layout for a running program. If a program is loaded but is not running, it should display the text segment address of the loaded program."},
    {"set", "set or s [running]: Set the value of a register"},
    {"si", "si [running]: Run a single instruction, and step into function calls."},
    {"start", "start [loaded]: Start the program and stop at the first instruction."},
    {"all", " - break {instruction-address}: add a break point\n - cont : continue execution\n - delete {break - point - id} : remove a break point\n - disasm addr : disassemble instructions in a file or a memory region\n - dump addr[length] : dump memory content\n - exit : terminate the debugger\n - get reg : get a single value from a register\n - getregs : show registers\n - help : show this message\n - list : list break points\n - load{path / to / a / program} : load a program\n - run : run the program\n - vmmap : show memory layout\n - set reg val : get a single value to a register\n - si : step into instruction\n - start : start the program and stop at the first instruction"}};

void errquit(const char *msg)
{
    perror(msg);
    exit(-1);
}

void printHelp(string type)
{
    if (type != "all")
        cout << "Warning: ";
    cout << helpmap[type] << endl;
    return;
}

void load(string path)
{
    programName = path;
    int i;
    elf_handle_t *eh = NULL;
    elf_strtab_t *tab = NULL;
    elf_init();

    if ((eh = elf_open(programName.c_str())) == NULL)
    {
        fprintf(stderr, "** unabel to open '%s'.\n", programName.c_str());
        return;
    }

    if (elf_load_all(eh) < 0)
    {
        fprintf(stderr, "** unable to load '%s.\n", programName.c_str());
        goto quit;
    }

    for (tab = eh->strtab; tab != NULL; tab = tab->next)
    {
        if (tab->id == eh->shstrndx)
            break;
    }
    if (tab == NULL)
    {
        fprintf(stderr, "** section header string table not found.\n");
        goto quit;
    }

    for (i = 0; i < eh->shnum; i++)
    {
        if (strcmp(".text", &tab->data[eh->shdr[i].name]) == 0)
        {
            entry = eh->shdr[i].addr;
            size = eh->shdr[i].size;
            offset = eh->shdr[i].offset;
            printf("** program '%s' loaded. entry point 0x%llx, vaddr 0x%llx, offset 0x%llx, size 0x%llx\n",
                   programName.c_str(),
                   eh->shdr[i].addr,
                   eh->shdr[i].addr,
                   eh->shdr[i].offset,
                   eh->shdr[i].size);
            break;
        }
    }
quit:
    if (eh)
    {
        elf_close(eh);
        eh = NULL;
    }
    status = LOADED;
}

void vmmap()
{
    if (status == LOADED)
    {
        printf("%016llx-%016llx r-x %llx      %s\n", entry, entry + size, offset, programName.c_str());
    }
    else
    {
        map<range_t, map_entry_t> m;
        map<range_t, map_entry_t>::iterator mi;
        if (waitpid(child, &wait_status, 0) < 0)
            errquit("waitpid");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        if (load_maps(child, m) > 0)
        {
            for (mi = m.begin(); mi != m.end(); mi++)
            {
                printf("%016lx-%016lx %s %-9ld %s\n",
                       mi->second.range.begin, mi->second.range.end,
                       mi->second.str_perm.c_str(), mi->second.offset, mi->second.name.c_str());
            }
        }
    }
}

void start()
{
    if ((child = fork()) < 0)
        errquit("fork");
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace");
        execlp(programName.c_str(), programName.c_str(), NULL);
        errquit("execvp");
    }
    else
    {
        cout << "** pid " << child << endl;
        status = RUNNING;
    }
}

void getreg(string regname)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, 0, &regs) == 0)
    {
        if (regname == "ALL")
        {
            printf("RAX %-18llxRBX %-18llxRCX %-18llxRDX %-18llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
            printf("R8  %-18llxR9  %-18llxR10 %-18llxR11 %-18llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
            printf("R12 %-18llxR13 %-18llxR14 %-18llxR15 %-18llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
            printf("RDI %-18llxRSI %-18llxRBP %-18llxRSP %-18llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
            printf("RIP %-18llxFLAGS %016llx\n", regs.rip, regs.eflags);
        }
        else
        {
            if (regname == "rip")
            {
                printf("rip = %lld (0x%llx)\n", regs.rip, regs.rip);
            }
            else if (regname == "rax")
            {
                printf("rax = %lld (0x%llx)\n", regs.rax, regs.rax);
            }
            else if (regname == "rbx")
            {
                printf("rbx = %lld (0x%llx)\n", regs.rbx, regs.rbx);
            }
            else if (regname == "rcx")
            {
                printf("rcx = %lld (0x%llx)\n", regs.rcx, regs.rcx);
            }
            else if (regname == "rdx")
            {
                printf("rdx = %lld (0x%llx)\n", regs.rdx, regs.rdx);
            }
            else if (regname == "r8")
            {
                printf("r8 = %lld (0x%llx)\n", regs.r8, regs.r8);
            }
            else if (regname == "r9")
            {
                printf("r9 = %lld (0x%llx)\n", regs.r9, regs.r9);
            }
            else if (regname == "r10")
            {
                printf("r10 = %lld (0x%llx)\n", regs.r10, regs.r10);
            }
            else if (regname == "r11")
            {
                printf("r11 = %lld (0x%llx)\n", regs.r11, regs.r11);
            }
            else if (regname == "r12")
            {
                printf("r12 = %lld (0x%llx)\n", regs.r12, regs.r12);
            }
            else if (regname == "r13")
            {
                printf("r13 = %lld (0x%llx)\n", regs.r13, regs.r13);
            }
            else if (regname == "r14")
            {
                printf("r14 = %lld (0x%llx)\n", regs.r14, regs.r14);
            }
            else if (regname == "r15")
            {
                printf("r15 = %lld (0x%llx)\n", regs.r15, regs.r15);
            }
            else if (regname == "rdi")
            {
                printf("rdi = %lld (0x%llx)\n", regs.rdi, regs.rdi);
            }
            else if (regname == "rsi")
            {
                printf("rsi = %lld (0x%llx)\n", regs.rsi, regs.rsi);
            }
            else if (regname == "rbp")
            {
                printf("rbp = %lld (0x%llx)\n", regs.rbp, regs.rbp);
            }
            else if (regname == "rsp")
            {
                printf("rsp = %lld (0x%llx)\n", regs.rsp, regs.rsp);
            }
            else if (regname == "eflags")
            {
                printf("eflags = %lld (0x%llx)\n", regs.eflags, regs.eflags);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        load(string(argv[1]));
    }

    int count = 0;
    size_t pos = 0;
    string input;
    string cmd;
    string args[2];
    while (true)
    {
        cout << "sdb> ";
        count = 0;
        getline(cin, input);
        while ((pos = input.find(' ')) != std::string::npos)
        {
            if (count == 0)
            {
                cmd = input.substr(0, pos);
            }
            else
            {
                args[count - 1] = input.substr(0, pos);
            }
            input.erase(0, pos + 1);
            ++count;
        }
        if (count == 0)
        {
            cmd = input;
        }
        else
        {
            args[count - 1] = input;
        }

        if (cmd == "help")
        {
            printHelp("all");
            continue;
        }
        else if (cmd == "load")
        {
            if (status == NOTLOADED)
            {
                load(args[0]);
                continue;
            }
            else
            {
                printHelp("load");
                continue;
            }
        }
        else if (cmd == "start")
        {
            if (status == LOADED)
            {
                start();
                continue;
            }
            else
            {
                printHelp("start");
                continue;
            }
        }
        else if (cmd == "vmmap" || cmd == "m")
        {
            if (status == LOADED || status == RUNNING)
            {
                vmmap();
                continue;
            }
            else
            {
                printHelp("vmmap");
                continue;
            }
        }
        else if (cmd == "get" || cmd == "g")
        {
            if (status == RUNNING)
            {
                getreg(args[0]);
            }
            else
            {
                printHelp("get");
                continue;
            }
        }
        else if (cmd == "getregs")
        {
            if (status == RUNNING)
            {
                getreg("ALL");
            }
            else
            {
                printHelp("get");
                continue;
            }
        }
        else if (cmd == "break" || cmd == "b")
        {
            if (status == LOADED || status == RUNNING)
            {
            }
            else
            {
                printHelp("break");
                continue;
            }
        }
        else if (cmd == "exit" || cmd == "q")
        {
            cout << "bye~" << endl;
            exit(0);
        }
    }
}