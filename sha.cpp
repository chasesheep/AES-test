#include "sha.h"
#include<cstring>
#include<cstdlib>
#include<ctime>

UI p[100];
ULL q[100];
unsigned char strs[1000];

int pad(unsigned char *str) {
    memset(p, 0, sizeof(p));
    int len = strlen((char *)str);
    str[len] = 0x80;
    int nlen = len + 1;
    if (nlen % 64 != 56) {
        nlen = ((nlen + 8) / 64) * 64 + 56;
    }
    for (int i = len + 1; i < nlen; i++) str[i] = '\0';
    nlen /= 4;
    for (int i = 0; i < nlen; i++) {
        UI a = str[i*4], b = str[i*4+1], c = str[i*4+2], d = str[i*4+3];
        p[i] = (a << 24) + (b << 16) + (c << 8) + d;
    }
    p[nlen] = 0;
    p[nlen+1] = len * 8;
    return (nlen+2) / 16;
}

void DoSHA256(const char* str) {
    memset(strs, 0, sizeof(strs));
    memcpy(strs, str, strlen(str));
    int n = pad(strs);
    //printf("%d\n", n);
    SHA256 t1;
    t1.calc(p, n);
}

void testSHA256() {
    DoSHA256("");
    DoSHA256("a");
    DoSHA256("abc");
    DoSHA256("message digest");
    DoSHA256("abcdefghijklmnopqrstuvwxyz");
    DoSHA256("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    DoSHA256("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

int main() {
    printf("SHA working!\n");
    testSHA256();
    return 0;
}
