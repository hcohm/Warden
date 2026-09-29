#include <unistd.h>
#include <stdlib.h>
int main(int c,char**v){sleep(c>1?atoi(v[1]):300);return 0;}
