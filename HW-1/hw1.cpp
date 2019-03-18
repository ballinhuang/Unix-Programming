#include <getopt.h>
#include <iostream>
#include <iomanip>

using namespace std;

void printConnections(string type, string filter)
{
    cout << type << " " << filter << endl;
}

int main(int argc, char *argv[])
{
    const char *optstring = "tu";
    int opt_index;
    struct option longopts[] = {
        {"tcp", 0, NULL, 't'},
        {"udp", 0, NULL, 'u'},
        {0, 0, 0, 0}};
    bool tcp_switch = false;
    bool udp_switch = false;
    string filter_string = "";

    while ((opt_index = getopt_long(argc, argv, optstring, longopts, NULL)) != -1)
    {
        switch (opt_index)
        {
        case 't':
            tcp_switch = true;
            break;
        case 'u':
            udp_switch = true;
            break;
        case '?':
            cout << "invalid" << endl;
            return 0;
        }
    }

    if (argc - optind > 1)
    {
        cout << "too many opt!" << endl;
        return 0;
    }

    if (argc == 1 || (argc == 2 && argv[optind] != NULL))
    {
        tcp_switch = true;
        udp_switch = true;
    }

    if (argv[optind] != NULL)
    {
        filter_string = string(argv[optind]);
    }

    if (tcp_switch)
    {
        cout << "List of TCP connections:" << endl;
        cout << left << setw(6) << "Proto" << setw(25) << "Local Address" << setw(25) << "Foreign Address"
             << "PID/Program name and arguments" << endl;
        printConnections("tcp", filter_string);
    }
    if (udp_switch)
    {
        if (tcp_switch)
            cout << endl;
        cout << "List of UDP connections:" << endl;
        cout << left << setw(6) << "Proto" << setw(25) << "Local Address" << setw(25) << "Foreign Address"
             << "PID/Program name and arguments" << endl;
        printConnections("udp", filter_string);
    }

    return 0;
}
