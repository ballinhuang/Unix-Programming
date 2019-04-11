#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main()
{
    FILE *pFile;
    char buffer[] = {'x', 'y', 'z'};
    pFile = fopen("test1.txt", "wb");
    fwrite(buffer, sizeof(char), sizeof(buffer), pFile);
    fclose(pFile);
    return 0;
}