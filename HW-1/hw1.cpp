#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>
#include <iomanip>
#include <cstdio>
#include <sstream>
#include <cctype>
#include <cstring>
#include <fstream>

using namespace std;

string porthex2string(int hexport)
{
    if (hexport == 0)
        return "*";
    stringstream ss;
    ss << dec << hexport;
    return ss.str();
}

void ipv4_hex2addr(struct in_addr hex_addr, char addr[INET_ADDRSTRLEN])
{
    inet_ntop(AF_INET, &hex_addr, addr, INET_ADDRSTRLEN * sizeof(char));
}

void ipv6_hex2addr(char str_addr[33], char addr[INET6_ADDRSTRLEN])
{
    struct in6_addr hex_addr;
    sscanf(str_addr, "%08X%08X%08X%08X",
           &hex_addr.s6_addr32[0], &hex_addr.s6_addr32[1], &hex_addr.s6_addr32[2], &hex_addr.s6_addr32[3]);
    inet_ntop(AF_INET6, &hex_addr, addr, INET6_ADDRSTRLEN * sizeof(char));
}

bool is_only_digit(char s[256])
{
    for (size_t i = 0; i < strlen(s); i++)
    {
        if (!isdigit(s[i]))
        {
            return false;
        }
    }
    return true;
}

string getPid(string inode)
{
    DIR *proc_dir = opendir("/proc");
    struct dirent *pid_dir_entry;
    if (proc_dir != NULL)
    {
        while (pid_dir_entry = readdir(proc_dir))
        {
            if (pid_dir_entry->d_type == DT_DIR && is_only_digit(pid_dir_entry->d_name))
            {
                DIR *fd_dir;
                string pid = string(pid_dir_entry->d_name);
                string fd_dir_path = "/proc/" + pid + "/fd";
                fd_dir = opendir(fd_dir_path.c_str());
                struct dirent *fd_dir_entry;
                while (fd_dir_entry = readdir(fd_dir))
                {
                    string fd_path = fd_dir_path + "/" + string(fd_dir_entry->d_name);
                    struct stat fd_stat;
                    stat(fd_path.c_str(), &fd_stat);
                    char link[1000];
                    if (S_ISSOCK(fd_stat.st_mode))
                    {
                        if (readlink(fd_path.c_str(), link, sizeof(link)))
                        {
                            if (strstr(link, inode.c_str()) != NULL)
                            {
                                return pid;
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        cerr << "Directory \"/proc\" access failed" << endl;
        exit(-1);
    }
}

string getCommad(string pid)
{
    string path = "/proc/" + pid + "/cmdline";
    string cmdline, arguments;
    fstream file;
    int pos;

    file.open(path.c_str(), ios::in);

    if (file)
    {
        getline(file, cmdline, '\0');
        if ((pos = cmdline.find_last_of("/")) != string::npos)
            cmdline.erase(0, pos + 1);

        while (getline(file, arguments, '\0'))
            cmdline += " " + arguments;
    }
    file.close();
    return cmdline;
}

void printConnection(string type, string src_ip, int src_port, string dis_ip, int dis_port, string pid, string cmd)
{

    cout << left << setw(6) << type
         << setw(25) << src_ip + ":" + porthex2string(src_port)
         << setw(25) << dis_ip + ":" + porthex2string(dis_port);
    cout << pid << "/" << cmd << endl;
}

void getIPV4Connections(string ipv4_path)
{
    /*
        sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5246513 1 0000000000000000 100  0   0  10  0
    */
    FILE *file = fopen(ipv4_path.c_str(), "r");
    if (file)
    {
        char header[1000];
        fgets(header, sizeof(header), file);

        struct in_addr src_addr, dis_addr;
        char src_ip[INET_ADDRSTRLEN], dis_ip[INET_ADDRSTRLEN];
        int src_port, dis_port;
        char inode[1000];

        while (fscanf(file, "%*s%x:%x%x:%x%*s%*s%*s%*s%*s%*s%s%*[^\n]\n", &src_addr.s_addr, &src_port, &dis_addr.s_addr, &dis_port, inode) != -1)
        {
            ipv4_hex2addr(src_addr, src_ip);
            ipv4_hex2addr(dis_addr, dis_ip);
            string pid = getPid(string(inode));
            string cmd = getCommad(pid);
            printConnection("tcp", string(src_ip), src_port, string(dis_ip), dis_port, pid, cmd);
        }
    }
    else
    {
        cout << ipv4_path << " access fail." << endl;
    }
}

void getIPV6Connections(string ipv6_path)
{
    /*
        sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        0: 00000000000000000000000001000000:0D16 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5251194 1 0000000000000000 100 0 0 10 0
    */
    FILE *file = fopen(ipv6_path.c_str(), "r");
    if (file)
    {
        char header[1000];
        fgets(header, sizeof(header), file);

        char src_addr_str[33], dis_addr_str[33];
        char src_ip[INET6_ADDRSTRLEN], dis_ip[INET6_ADDRSTRLEN];
        int src_port, dis_port;
        char inode[1000];

        while (fscanf(file, "%*s %[^:]:%x%[^:]:%x%*s%*s%*s%*s%*s%*s%s%*[^\n]\n", src_addr_str, &src_port, dis_addr_str, &dis_port, inode) != -1)
        {
            ipv6_hex2addr(src_addr_str, src_ip);
            ipv6_hex2addr(dis_addr_str, dis_ip);
            string pid = getPid(string(inode));
            string cmd = getCommad(pid);
            printConnection("tcp6", string(src_ip), src_port, string(dis_ip), dis_port, pid, cmd);
        }
    }
    else
    {
        cout << ipv6_path << " access fail." << endl;
    }
}

void getConnections(string type, string filter)
{
    string ipv4_path = "/proc/net/" + type;
    string ipv6_path = "/proc/net/" + type + "6";
    getIPV4Connections(ipv4_path);
    getIPV6Connections(ipv6_path);
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
        getConnections("tcp", filter_string);
    }
    if (udp_switch)
    {
        if (tcp_switch)
            cout << endl;
        cout << "List of UDP connections:" << endl;
        cout << left << setw(6) << "Proto" << setw(25) << "Local Address" << setw(25) << "Foreign Address"
             << "PID/Program name and arguments" << endl;
        getConnections("udp", filter_string);
    }

    return 0;
}
