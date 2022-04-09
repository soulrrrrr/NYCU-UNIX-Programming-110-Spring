#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
int main() {
    int fd = open("test.txt", O_RDONLY);
    chmod("test.txt", 0777);
    chown("test.txt", 1001, 1001);
    int fd2 = open("test2.txt", O_WRONLY | O_CREAT, 0644);
    close(fd2);
    int fd3 = creat("test3.txt", 0640);
    close(fd);
    FILE *fp = fopen("test.txt", "r+");
    char c[100] = {0};
    fread(c, sizeof *c, 40, fp);
    fwrite("1234567890", sizeof *c, 10, fp);
    printf("%s\n", c);
    close(fd3);
    fclose(fp);

    return 0;
}
