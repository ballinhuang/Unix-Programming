#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

void checkOuputEnv(void) __attribute__((constructor));
void _exit() __attribute__((destructor));

/*
    dirent.h(P)
*/
// int dirfd(DIR *dirp);
typedef int (*fp_closedir_t)(DIR *dirp);
// DIR *opendir(const char *name);
typedef DIR *(*fp_opendir_t)(const char *name);
// struct dirent *readdir(DIR *dirp);
typedef struct dirent *(*fp_readdir_t)(DIR *dirp);

/*
    fcntl.h(P)
*/
// int creat(const char *path, mode_t mode);
typedef int (*fp_creat_t)(const char *path, mode_t mode);
// int open(const char *pathname, int flags, mode_t mode);
typedef int (*fp_open_t)(const char *pathname, int flags, mode_t mode);

/*
    stdio.h(P)
*/
// FILE *fopen(const char *path, const char *mode);     [FAIL]
typedef FILE *(*fp_fopen_t)(const char *path, const char *mode);
// int fclose(FILE *stream);        [FAIL]
typedef int (*fp_fclose_t)(FILE *stream);
// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
typedef size_t (*fp_fread_t)(void *ptr, size_t size, size_t nmemb, FILE *stream);
// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
typedef size_t (*fp_fwrite_t)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
// int fscanf(FILE *stream, const char *format, ...);
typedef int (*fp_fscanf_t)(FILE *stream, const char *format, ...);
// int fprintf(FILE *stream, const char *format, ...);
typedef int (*fp_fprintf_t)(FILE *stream, const char *format, ...);
// int remove(const char *pathname);
typedef int (*fp_remove_t)(const char *pathname);
// int rename(const char *oldname, const char *newname);
typedef int (*fp_rename_t)(const char *oldname, const char *newname);
// int fgetc(FILE *stream);
typedef int (*fp_fgetc_t)(FILE *stream);
// char *fgets(char *s, int size, FILE *stream);
typedef char *(*fp_fgets_t)(char *s, int size, FILE *stream);

/*
    stdlib.h(P)
*/
// char* getenv (const char* name);
typedef char *(*fp_getenv_t)(const char *name);

/*
    unistd.h(P)
*/
// ssize_t read(int fildes, void *buf, size_t nbyte);
typedef ssize_t (*fp_read_t)(int fildes, void *buf, size_t nbyte);
// ssize_t write(int fildes, const void *buf, size_t nbyte);
typedef ssize_t (*fp_write_t)(int fildes, const void *buf, size_t nbyte);
// int dup(int fildes);
typedef int (*fp_dup_t)(int fildes);
// int dup2(int fildes, int fildes2);
typedef int (*fp_dup2_t)(int fildes, int fildes2);
// int close(int fildes);
typedef int (*fp_close_t)(int fildes);
// int chdir(const char *path);
typedef int (*fp_chdir_t)(const char *path);
// int chown(const char *path, uid_t owner, gid_t group);
typedef int (*fp_chown_t)(const char *path, uid_t owner, gid_t group);
// ssize_t readlink(const char *path, char *buf, size_t bufsiz);
typedef ssize_t (*fp_readlink_t)(const char *path, char *buf, size_t bufsiz);
// int link(const char *path1, const char *path2);
typedef int (*fp_link_t)(const char *path1, const char *path2);
// int unlink(const char *path);
typedef int (*fp_unlink_t)(const char *path);
// int symlink(const char *path1, const char *path2);
typedef int (*fp_symlink_t)(const char *path1, const char *path2);
// int rmdir(const char *path);
typedef int (*fp_rmdir_t)(const char *path);
// ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset);
typedef ssize_t (*fp_pwrite_t)(int fildes, const void *buf, size_t nbyte, off_t offset);

/*
    sys_stat.h(7POSIX)
*/
// int chmod(const char *path, mode_t mode);
typedef int (*fp_chmod_t)(const char *path, mode_t mode);
// int mkdir(const char *path, mode_t mode);
typedef int (*fp_mkdir_t)(const char *path, mode_t mode);
// int __lxstat(int __ver, const char *path, struct stat *buf);
typedef int (*fp_lxstat_t)(int __ver, const char *path, struct stat *buf);
// int __xstat(int __ver, const char * path, struct stat * buf);
typedef int (*fp_xstat_t)(int __ver, const char *path, struct stat *buf);