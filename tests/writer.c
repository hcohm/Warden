// Holds a file open for writing and appends 1 MB every 100 ms for the given seconds.
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int c, char **v) {
    if (c < 3) return 1;
    int fd = open(v[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    static char buf[1 << 20];
    memset(buf, 'x', sizeof buf);
    for (int i = 0; i < atoi(v[2]) * 10; i++) { write(fd, buf, sizeof buf); fsync(fd); usleep(100000); }
    close(fd);
    return 0;
}
