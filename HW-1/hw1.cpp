#include <getopt.h>
#include <iostream>

using namespace std;

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
    string filter_string;

    while ((opt_index = getopt_long(argc, argv, optstring, longopts, NULL)) != -1)
    {
        switch (opt_index)
        {
        case 't':
            tcp_switch = true;
            cout << "tcp open." << endl;
            break;
        case 'u':
            udp_switch = true;
            cout << "udp open." << endl;
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
        cout << "fiter:" << filter_string << endl;
    }

    return 0;
}
