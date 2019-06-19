#include <assert.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <iostream>

#include "ptools.h"

using namespace std;

#define NOTLOADED 0
#define LOADED 1
#define RUNNING 2

int status = 0;
string programName = "";
pid_t child;

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
    if ((child = fork()) < 0)
        errquit("fork");
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace");
        execlp(programName.c_str(), programName.c_str(), NULL);
        errquit("execvp");
    }
}

int main(int argc, char *argv[])
{
    /*
    if (argc > 1)
    {
        programName = string(argv[1]);
    }
    */
    int count = 0;
    size_t pos = 0;
    string input;
    string cmd;
    string args[2];
    while (true)
    {
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