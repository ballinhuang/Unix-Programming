#include <stdio.h>

void loadGnuLibrary(void) __attribute__((constructor));
void checkOuputEnv(void) __attribute__((constructor));
void _exit() __attribute__((destructor));

/*
    stdio.h(P)
*/
// int open(const char *path, int oflag, ... )
typedef int (*fp_open_t)(const char *path, int oflag, ...);
// FILE * fopen ( const char * filename, const char * mode );
typedef FILE *(*fp_fopen_t)(const char *filename, const char *mode);

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
//ssize_t readlink(const char *path, char *buf, size_t bufsiz);
typedef ssize_t (*fp_readlink_t)(const char *path, char *buf, size_t bufsiz);
