#include "LCM.hpp"
#include <fstream>
#include <dlfcn.h>
#include <stdarg.h>
#include <string>
#include <iostream>

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
        return std::to_string(fd);
    else
        path[n] = '\0';
    return "\"" + std::string(path) + "\"";
}

extern "C"
{
    /*
        dirent.h(P)
    */
    int closedir(DIR *dirp)
    {
        std::string path = getPathByFd(dirfd(dirp));
        fp_closedir_t org_closedir = (fp_closedir_t)dlsym(originalhandler, "closedir");
        int result = org_closedir(dirp);
        fprintf(output, "# %s(%s) = %d\n", __func__, path.c_str(), result);

        return result;
    }
    DIR *opendir(const char *name)
    {
        fp_opendir_t org_opendir = (fp_opendir_t)dlsym(originalhandler, "opendir");
        DIR *result = org_opendir(name);
        fprintf(output, "# %s(\"%s\") = %p\n", __func__, name, result);
        return result;
    }

    struct dirent *readdir(DIR *dirp)
    {
        std::string path = getPathByFd(dirfd(dirp));
        fp_readdir_t org_readdir = (fp_readdir_t)dlsym(originalhandler, "readdir");
        struct dirent *result = org_readdir(dirp);
        if (result)
            fprintf(output, "# %s(%s) = %s\n", __func__, path.c_str(), result->d_name);
        else
            fprintf(output, "# %s(%s) = %p\n", __func__, path.c_str(), result);

        return result;
    }
    /*
        fcntl.h(P)
    */
    int creat(const char *path, mode_t mode)
    {
        fp_creat_t org_creat = (fp_creat_t)dlsym(originalhandler, "creat");
        int result = org_creat(path, mode);
        fprintf(output, "# %s(\"%s\", %08o) = %d\n", __func__, path, mode, result);
        return result;
    }

    /*
        stdio.h(P)
    */
    int open(const char *pathname, int flags, mode_t mode)
    {
        fp_open_t org_open = (fp_open_t)dlsym(originalhandler, "open");

        int result;
        result = org_open(pathname, flags, mode);
        fprintf(output, "# %s(\"%s\", 0x%x) = %d\n", __func__, pathname, flags, result);
        //TBD

        return result;
    }

    /*
        unistd.h(P)
    */
    ssize_t read(int fildes, void *buf, size_t nbyte)
    {
        std::string path = getPathByFd(fildes);
        fp_read_t org_read = (fp_read_t)dlsym(originalhandler, "read");
        ssize_t result = org_read(fildes, buf, nbyte);
        fprintf(output, "# %s(%s, %p, %zd) = %zd\n", __func__, path.c_str(), buf, nbyte, result);

        return result;
    }
    ssize_t write(int fildes, const void *buf, size_t nbyte)
    {
        std::string path = getPathByFd(fildes);
        fp_write_t org_write = (fp_write_t)dlsym(originalhandler, "write");
        ssize_t result = org_write(fildes, buf, nbyte);
        fprintf(output, "# %s(%s, %p, %zd) = %zd\n", __func__, path.c_str(), buf, nbyte, result);
        return result;
    }
    int dup(int fildes)
    {
        std::string path = getPathByFd(fildes);
        fp_dup_t org_dup = (fp_dup_t)dlsym(originalhandler, "dup");
        int result = org_dup(fildes);
        fprintf(output, "# %s(%s) = %d\n", __func__, path.c_str(), result);
        return result;
    }
    int dup2(int fildes, int fildes2)
    {
        std::string path1 = getPathByFd(fildes);
        std::string path2 = getPathByFd(fildes2);
        fp_dup2_t org_dup2 = (fp_dup2_t)dlsym(originalhandler, "dup2");
        int result = org_dup2(fildes, fildes2);
        fprintf(output, "# %s(%s, %s) = %d\n", __func__, path1.c_str(), path2.c_str(), result);
        return result;
    }
    int close(int fildes)
    {
        std::string path = getPathByFd(fildes);
        fp_close_t org_close = (fp_close_t)dlsym(originalhandler, "close");
        int result = org_close(fildes);
        fprintf(output, "# %s(%s) = %d\n", __func__, path.c_str(), result);
        return result;
    }
}