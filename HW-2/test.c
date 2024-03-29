#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>

#define MAXLINE 1024

int main(int argc, char *argv[], char **envp)
{
    int value;
    char buf[MAXLINE];
    fgets(buf, 10, stdin);
    fgetc(stdin);

    fscanf(stdin, "%d", &value);
    fprintf(stdout, "Value [%d]\n", value);

    DIR *d;
    mkdir("./tempdir", 0777);
    d = opendir("./tempdir");
    rename("./tempdir", "./tempdir2");
    struct dirent *ptr;
    while ((ptr = readdir(d)) != NULL)
        ;
    closedir(d);

    FILE *file;
    char buffer[] = {'x', 'y', 'z'};
    size_t result;
    creat("./temp", 0755);
    rename("./temp", "./temp2");
    file = fopen("./temp2", "rw");
    result = fread(buf, 1, sizeof(buf), file);
    fwrite(buffer, sizeof(char), sizeof(buffer), file);
    fclose(file);

    int fd_creat = open("./temp3", O_RDWR | O_CREAT, S_IRWXU);
    int fd = open("./temp2", O_RDWR);
    pwrite(fd, buffer, 1, 0);
    read(fd, buf, 1);
    write(fd, buffer, 1);
    close(fd);

    chdir("./tempdir2");
    chdir("..");
    chown("./temp2", 1000, 1000);
    chmod("./temp2", 0777);

    int pipefd[2];
    pipe(pipefd);
    dup(pipefd[0]);
    dup2(1, pipefd[1]);

    link("./temp2", "./temp2_link");
    symlink("./temp2", "./temp2_slink");
    readlink("./temp2_slink", buf, sizeof(buf));
    unlink("./temp2_link");
    unlink("./temp2_slink");

    struct stat statbuf;
    lstat("./temp2", &statbuf);
    stat("./temp2", &statbuf);

    remove("./temp3");
    remove("./temp2");
    rmdir("./tempdir2");

    return 0;
}
