#include "AES.h"

void testSbox() {
    for (unsigned char i = 0; ; i++) {
        if (getIS(getS(i)) != i) {
            printf("Sbox verification error! err = 0x%02x\n", i);
            return;
        }
        if (i == 0xFF) break;
    }
    printf("Sbox verification success!\n");
}

int main() {
    printf("AES encryption and decryption program\n");
    testSbox();
    return 0;
}
