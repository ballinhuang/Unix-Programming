#include "LCM.hpp"
#include <fstream>
#include <dlfcn.h>
#include <stdarg.h>
#include <string>

void *originalhandler;
FILE *output;

void loadGnuLibrary(void)
{
    originalhandler = dlopen("libc.so.6", RTLD_LAZY);
}

void checkOuputEnv(void)
{
    fp_getenv_t org_getenv = (fp_getenv_t)dlsym(originalhandler, "getenv");
    char *outputenv = org_getenv("MONITOR_OUTPUT");

    if (outputenv != NULL)
    {
        fp_fopen_t org_fopen = (fp_fopen_t)dlsym(originalhandler, "fopen");
        output = org_fopen(outputenv, "w");
    }
    else
    {
        output = stderr;
    }
}

void _exit()
{
    dlclose(originalhandler);
    fclose(output);
}

std::string getPathByFd(int fd)
{
    std::string fdpath = "/proc/self/fd/" + std::to_string(fd);
    fp_readlink_t org_readlink = (fp_readlink_t)dlsym(originalhandler, "readlink");
    char path[4096];
    int n = org_readlink(fdpath.c_str(), path, sizeof(path));
    if (n < 0)
        return "";
    else
        path[n] = '\0';

    return std::string(path);
}

extern "C"
{
    /*
        stdio.h(P)
    */
    int open(const char *pathname, int flags)
    {
        fp_open_t org_open = (fp_open_t)dlsym(originalhandler, "open");
        int result = org_open(pathname, flags);
        fprintf(output, "# %s(\"%s\", 0x%x) = %d\n", __func__, pathname, flags, result);

        return result;
    }

    /*
        unistd.h(P)
    */
    ssize_t read(int fildes, void *buf, size_t nbyte)
    {
        fp_read_t org_read = (fp_read_t)dlsym(originalhandler, "read");
        ssize_t result = org_read(fildes, buf, nbyte);
        fprintf(output, "# %s(%s, %p, %zu) = %zd\n", __func__, getPathByFd(fildes).c_str(), buf, nbyte, result);

        return result;
    }
}