#include "LCM.hpp"
#include <fstream>
#include <dlfcn.h>
#include <stdarg.h>
#include <string>
#include <iostream>

#define originalhandler RTLD_NEXT
FILE *output;
fp_fprintf_t org_fprintf;

void checkOuputEnv(void)
{
    fp_getenv_t org_getenv = (fp_getenv_t)dlsym(originalhandler, "getenv");
    char *outputenv = org_getenv("MONITOR_OUTPUT");
    org_fprintf = (fp_fprintf_t)dlsym(originalhandler, "fprintf");

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
    fp_fclose_t org_fclose = (fp_fclose_t)dlsym(originalhandler, "fclose");
    org_fclose(output);
}

std::string getPathByFd(int fd)
{
    if (fd == 0)
        return "\"<STDIN>\"";
    else if (fd == 1)
        return "\"<STDOUT>\"";
    else if (fd == 2)
        return "\"<STDERR>\"";
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
        org_fprintf(output, "# %s(%s) = %d\n", __func__, path.c_str(), result);

        return result;
    }
    DIR *opendir(const char *name)
    {
        fp_opendir_t org_opendir = (fp_opendir_t)dlsym(originalhandler, "opendir");
        DIR *result = org_opendir(name);
        org_fprintf(output, "# %s(\"%s\") = %p\n", __func__, name, result);
        return result;
    }

    struct dirent *readdir(DIR *dirp)
    {
        std::string path = getPathByFd(dirfd(dirp));
        fp_readdir_t org_readdir = (fp_readdir_t)dlsym(originalhandler, "readdir");
        struct dirent *result = org_readdir(dirp);
        if (result)
            org_fprintf(output, "# %s(%s) = \"%s\"\n", __func__, path.c_str(), result->d_name);
        else
            org_fprintf(output, "# %s(%s) = %p\n", __func__, path.c_str(), result);

        return result;
    }
    /*
        fcntl.h(P)
    */
    int creat(const char *path, mode_t mode)
    {
        fp_creat_t org_creat = (fp_creat_t)dlsym(originalhandler, "creat");
        int result = org_creat(path, mode);
        org_fprintf(output, "# %s(\"%s\", %08o) = %d\n", __func__, path, mode, result);
        return result;
    }

    /*
        stdio.h(P)
    */
    FILE *fopen(const char *path, const char *mode)
    {
        fp_fopen_t org_fopen = (fp_fopen_t)dlsym(originalhandler, "fopen");
        FILE *result = org_fopen(path, mode);
        //org_fprintf(output, "# %s(const char *path, const char *mode) = result\n", __func__);
        printf("# %s(\"%s\", \"%s\") = %p\n", __func__, path, mode, result);
        return result;
    }
    int fclose(FILE *stream)
    {
        std::string path = getPathByFd(fileno(stream));
        fp_fclose_t org_fclose = (fp_fclose_t)dlsym(originalhandler, "fclose");
        int result = org_fclose(stream);
        //org_fprintf(output, "# %s(%s) = %d\n", __func__, path.c_str(), result);
        printf("# %s(%s) = %d\n", __func__, path.c_str(), result);
        return result;
    }
    size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
    {
        std::string path = getPathByFd(fileno(stream));
        fp_fread_t org_fread = (fp_fread_t)dlsym(originalhandler, "fread");
        size_t result = org_fread(ptr, size, nmemb, stream);
        org_fprintf(output, "# %s(%p, %zd, %zd, %s) = %zd\n", __func__, ptr, size, nmemb, path.c_str(), result);
        return result;
    }
    size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
    {
        std::string path = getPathByFd(fileno(stream));
        fp_fwrite_t org_fwrite = (fp_fwrite_t)dlsym(originalhandler, "fwrite");
        size_t result = org_fwrite(ptr, size, nmemb, stream);
        org_fprintf(output, "# %s(%p, %zd, %zd, %s) = %zd\n", __func__, ptr, size, nmemb, path.c_str(), result);
        return result;
    }
    int __isoc99_fscanf(FILE *stream, const char *format, ...)
    {
        std::string path = getPathByFd(fileno(stream));
        va_list arg;
        va_start(arg, format);
        int result = vfscanf(stream, format, arg);
        org_fprintf(output, "# %s(%s, \"%s\", ...) = %d\n", "fscanf", path.c_str(), format, result);
        va_end(arg);
        org_fprintf(output, "%d\n", fileno(stream));
        return result;
    }
    int fprintf(FILE *stream, const char *format, ...)
    {
        std::string path = getPathByFd(fileno(stream));
        va_list arg;
        va_start(arg, format);
        int result = vfprintf(stream, format, arg);
        org_fprintf(output, "# %s(%s, \"%s\", ...) = %d\n", __func__, path.c_str(), format, result);
        va_end(arg);
        return result;
    }
    int remove(const char *pathname)
    {
        fp_remove_t org_remove = (fp_remove_t)dlsym(originalhandler, "remove");
        int result = org_remove(pathname);
        org_fprintf(output, "# %s(\"%s\") = %d\n", __func__, pathname, result);
        return result;
    }
    int rename(const char *oldname, const char *newname)
    {
        fp_rename_t org_rename = (fp_rename_t)dlsym(originalhandler, "rename");
        int result = org_rename(oldname, newname);
        org_fprintf(output, "# %s(\"%s\", \"%s\") = %d\n", __func__, oldname, newname, result);
        return result;
    }
    int fgetc(FILE *stream)
    {
        std::string path = getPathByFd(fileno(stream));
        fp_fgetc_t org_fgetc = (fp_fgetc_t)dlsym(originalhandler, "fgetc");
        int result = org_fgetc(stream);
        org_fprintf(output, "# %s(%s) = %c\n", __func__, path.c_str(), result);
        return result;
    }
    char *fgets(char *s, int size, FILE *stream)
    {
        std::string path = getPathByFd(fileno(stream));
        fp_fgets_t org_fgets = (fp_fgets_t)dlsym(originalhandler, "fgets");
        char *result = org_fgets(s, size, stream);
        org_fprintf(output, "# %s(\"%s\", %d, %s) = %c\n", __func__, s, size, path.c_str(), result);
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
        org_fprintf(output, "# %s(%s, %p, %zd) = %zd\n", __func__, path.c_str(), buf, nbyte, result);

        return result;
    }
    ssize_t write(int fildes, const void *buf, size_t nbyte)
    {
        std::string path = getPathByFd(fildes);
        fp_write_t org_write = (fp_write_t)dlsym(originalhandler, "write");
        ssize_t result = org_write(fildes, buf, nbyte);
        org_fprintf(output, "# %s(%s, %p, %zd) = %zd\n", __func__, path.c_str(), buf, nbyte, result);
        return result;
    }
    int dup(int fildes)
    {
        std::string path = getPathByFd(fildes);
        fp_dup_t org_dup = (fp_dup_t)dlsym(originalhandler, "dup");
        int result = org_dup(fildes);
        org_fprintf(output, "# %s(%s) = %d\n", __func__, path.c_str(), result);
        return result;
    }
    int dup2(int fildes, int fildes2)
    {
        std::string path1 = getPathByFd(fildes);
        std::string path2 = getPathByFd(fildes2);
        fp_dup2_t org_dup2 = (fp_dup2_t)dlsym(originalhandler, "dup2");
        int result = org_dup2(fildes, fildes2);
        org_fprintf(output, "# %s(%s, %s) = %d\n", __func__, path1.c_str(), path2.c_str(), result);
        return result;
    }
    int close(int fildes)
    {
        std::string path = getPathByFd(fildes);
        fp_close_t org_close = (fp_close_t)dlsym(originalhandler, "close");
        int result = org_close(fildes);
        org_fprintf(output, "# %s(%s) = %d\n", __func__, path.c_str(), result);
        return result;
    }
    int chdir(const char *path)
    {
        fp_chdir_t org_chdir = (fp_chdir_t)dlsym(originalhandler, "chdir");
        int result = org_chdir(path);
        org_fprintf(output, "# %s(\"%s\") = %d\n", __func__, path, result);
        return result;
    }
    int chown(const char *path, uid_t owner, gid_t group)
    {
        fp_chown_t org_chown = (fp_chown_t)dlsym(originalhandler, "chown");
        int result = org_chown(path, owner, group);
        org_fprintf(output, "# %s(\"%s\", %d, %d) = %d\n", __func__, path, owner, group, result);
        return result;
    }
    int link(const char *path1, const char *path2)
    {
        fp_link_t org_link = (fp_link_t)dlsym(originalhandler, "link");
        int result = org_link(path1, path2);
        org_fprintf(output, "# %s(\"%s\", \"%s\") = %d\n", __func__, path1, path2, result);
        return result;
    }
    int unlink(const char *path)
    {
        fp_unlink_t org_unlink = (fp_unlink_t)dlsym(originalhandler, "unlink");
        int result = org_unlink(path);
        org_fprintf(output, "# %s(\"%s\") = %d\n", __func__, path, result);
        return result;
    }
    ssize_t readlink(const char *path, char *buf, size_t bufsiz)
    {
        fp_readlink_t org_readlink = (fp_readlink_t)dlsym(originalhandler, "readlink");
        int result = org_readlink(path, buf, bufsiz);
        org_fprintf(output, "# %s(\"%s\", \"%s\", %zd) = %d\n", __func__, path, buf, bufsiz, result);
        return result;
    }
    int symlink(const char *path1, const char *path2)
    {
        fp_symlink_t org_symlink = (fp_symlink_t)dlsym(originalhandler, "symlink");
        int result = org_symlink(path1, path2);
        org_fprintf(output, "# %s(\"%s\", \"%s\") = %d\n", __func__, path1, path2, result);
        return result;
    }
    int rmdir(const char *path)
    {
        fp_rmdir_t org_rmdir = (fp_rmdir_t)dlsym(originalhandler, "rmdir");
        int result = org_rmdir(path);
        org_fprintf(output, "# %s(\"%s\") = %d\n", __func__, path, result);
        return result;
    }
    ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset)
    {
        std::string path = getPathByFd(fildes);
        fp_pwrite_t org_pwrite = (fp_pwrite_t)dlsym(originalhandler, "pwrite");
        ssize_t result = org_pwrite(fildes, buf, nbyte, offset);
        org_fprintf(output, "# %s(%s, %p, %zd, %ld) = %zd\n", __func__, path.c_str(), buf, nbyte, offset, result);
        return result;
    }

    /*
        sys_stat.h(7POSIX)
    */
    int open(const char *pathname, int flags, mode_t mode)
    {
        fp_open_t org_open = (fp_open_t)dlsym(originalhandler, "open");

        int result;
        result = org_open(pathname, flags, mode);
        org_fprintf(output, "# %s(\"%s\", 0x%x) = %d\n", __func__, pathname, flags, result);
        //TBD

        return result;
    }
    int chmod(const char *path, mode_t mode)
    {
        fp_chmod_t org_chmod = (fp_chmod_t)dlsym(originalhandler, "chmod");
        int result = org_chmod(path, mode);
        org_fprintf(output, "# %s(\"%s\",%o) = %d\n", __func__, path, mode, result);
        return result;
    }
    int mkdir(const char *path, mode_t mode)
    {
        fp_mkdir_t org_mkdir = (fp_mkdir_t)dlsym(originalhandler, "mkdir");
        int result = org_mkdir(path, mode);
        org_fprintf(output, "# %s(\"%s\", %o) = %d\n", __func__, path, mode, result);
        return result;
    }
    int __lxstat(int __ver, const char *path, struct stat *buf)
    {
        fp_lxstat_t org_lxstat = (fp_lxstat_t)dlsym(originalhandler, "__lxstat");
        int result = org_lxstat(__ver, path, buf);
        org_fprintf(output, "# %s(\"%s\", %p {dev=%d, ino=%d, mode=%05o, uid=%d, gid=%d, size=%ld}) = %d\n", "lstat", path,
                    buf, buf->st_dev, buf->st_ino, buf->st_mode, buf->st_uid, buf->st_gid, buf->st_size, result);
        return result;
    }
    int __xstat(int __ver, const char *path, struct stat *buf)
    {
        fp_xstat_t org_xstat = (fp_xstat_t)dlsym(originalhandler, "__xstat");
        int result = org_xstat(__ver, path, buf);
        org_fprintf(output, "# %s(\"%s\", %p {dev=%d, ino=%d, mode=%05o, uid=%d, gid=%d, size=%ld}) = %d\n", "stat", path,
                    buf, buf->st_dev, buf->st_ino, buf->st_mode, buf->st_uid, buf->st_gid, buf->st_size, result);
        return result;
    }
}