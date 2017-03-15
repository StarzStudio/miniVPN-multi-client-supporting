#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void randomize(unsigned char *buf, int len)
{
    FILE *random = fopen("/dev/urandom", "r");
    fread(buf, sizeof(unsigned char)*len, 1, random);
    fclose(random);
}


int main()
{
    unsigned char  salt[4];
    randomize(salt, sizeof(salt));
    FILE * f = fopen("salt", "wb");
    fwrite(salt, sizeof(salt), 1, f);
    fclose(f);
}