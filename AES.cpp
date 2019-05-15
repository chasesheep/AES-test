#include "AES.h"
#include<cstdlib>
#include<cstring>
#include<ctime>

#define shortM 16384
#define longM 10485760

int keys[8] = {};
int output[4] = {};
UC* message, *Omessage, *Pmessage;

int pad(int len) {
    return (len & 0xF) ? (len & 0xFFFFFFF0) + 16 : len;
}
int genMessage(int len) {
    int nlen = pad(len);
    message = new UC[nlen];
    memset(message, 0, nlen);
    for (int i = 0; i < len; i++) message[i] = (UC) rand();    ///or we could read message here
    return nlen;
}

void testEncryptMessage(int length, int type) {
    int nlen;
    keys[0] = 0x03020100;
    keys[1] = 0x07060504;
    keys[2] = 0x0b0a0908;
    keys[3] = 0x0f0e0d0c;
    keys[4] = 0x13121110;
    keys[5] = 0x17161514;    ///given key

    nlen = genMessage(length);
    Omessage = new UC[nlen];
    Pmessage = new UC[nlen];                ///buffer for output
    memset(Omessage, 0, nlen);
    memset(Pmessage, 0, nlen);

    //for (int i = 0; i < nlen; i++) printf("%02x", message[i]); putchar('\n');

    //printf("Preparing test...\n");

    time_t t0 = clock();

    ///Encrypt
    CBC_AES solver;
    solver.initKeys(type, keys);
    for (int i = 0; i < 4; i++) solver.IV[i] = 0;
    solver.encrypt(message, Omessage, nlen);

    //for (int i = 0; i < nlen; i++) printf("%02x", Omessage[i]); putchar('\n');

    time_t t1 = clock();
    //printf("Encrypt\n");

    ///Decrypt
    CBC_AES de_solver;
    de_solver.initKeys(type, keys);
    for (int i = 0; i < 4; i++) de_solver.IV[i] = 0;
    de_solver.decrypt(Omessage, Pmessage, nlen);

    //for (int i = 0; i < nlen; i++) printf("%02x", Pmessage[i]); putchar('\n');

    time_t t2 = clock();
    //printf("Decrypt\n");

    ///Verify
    bool ok = true;
    for (int i = 0; i < nlen; i++) if (message[i] != Pmessage[i]) {
        ok = false; break;
    }
    if (ok) printf("Test success!\n"); else printf("Test failed!\n");

    //printf("%d\n", CLOCKS_PER_SEC);
    printf("Type: AES-%d; Length(bytes): %d; ", type, length);
    //printf("Time: %d %d %d\n", t0, t1, t2);

    float dt0 = ((float)(t1-t0))/CLOCKS_PER_SEC, dt1 = ((float)(t2-t1))/CLOCKS_PER_SEC;
    printf("Encrypt time: %fs; Decrypt time: %fs\n", dt0, dt1);

    delete [] message;
    delete [] Omessage;
    delete [] Pmessage;

}

void testRand() {
    for (int i = 0; i < 20; i++) printf("%d ", (UC) rand());
    putchar('\n');
}

void testSbox() {
    for (UC i = 0; ; i++) {
        if (getIS(getS(i)) != i) {
            printf("Sbox verification error! err = 0x%02x\n", i);
            return;
        }
        if (i == 0xFF) break;
    }
    printf("Sbox verification success!\n");
}

void testMatrix() {
    AES temp;
    UC test[4][4] = {
        0xc9, 0x7a, 0x63, 0xb0,
        0xe5, 0xf2, 0x9c, 0xa7,
        0xfd, 0x78, 0x26, 0x82,
        0x2b, 0x6e, 0x67, 0xe5
    };
    for (UC i = 0; i < 4; i++)
        for (UC j = 0; j < 4; j++) temp.state[i][j] = test[i][j];
    //temp.print();
    temp.MixColumns(1);
    //temp.print();
    temp.MixColumns(0);
    //temp.print();
    for (UC i = 0; i < 4; i++)
        for (UC j = 0; j < 4; j++)
        if (temp.state[i][j] != test[i][j]) {
            printf("Mixcolumn test failed\n");
            return;
        }
    printf("Mixcolumn test success!\n");

    temp.print();
    temp.ShiftRows();
    temp.print();
    temp.DeShiftRows();
    temp.print();
}

void testMult(UC a, UC b) {
    printf("0x%02x 0x%02x 0x%02x\n", a, b, mult(a, b));
}

void testCI() {
    UC b[4] = {0x1, 0x2, 0x3, 0x4};
    int *integer = (int*) &(b[0]);
    printf("%08x\n", *integer);
    *integer = rotateL(*integer);
    printf("%08x\n", *integer);
    for (int i = 0; i < 4; i++) printf("0x%02x ", b[i]);
    putchar('\n');
}

void testRConj() {
    AES temp;
    temp.initKeys(256, keys);
}

void testKeystream() {
    AES temp;
    keys[0] = 0x210ba13c;
    keys[1] = 0x1619f057;
    keys[2] = 0x80132e90;
    keys[3] = 0xbd07c1ac;
    temp.initKeys(128, keys);
    temp.generateKeys();
    for (int i = 4; i < 8; i++) printf("%08x ", temp.keystream[i]);
    putchar('\n');
}

void testAES128() {
    AES temp;
    keys[0] = 0x03020100;
    keys[1] = 0x07060504;
    keys[2] = 0x0b0a0908;
    keys[3] = 0x0f0e0d0c;
    temp.initKeys(128, keys);

    UC test[4][4] = {
        0xe5, 0x4b, 0x04, 0x09,
        0x9c, 0x6c, 0x16, 0xba,
        0x14, 0xa0, 0xe2, 0x5f,
        0x4f, 0xb6, 0x8d, 0xd4
    };

    for (UC i = 0; i < 4; i++)
        for (UC j = 0; j < 4; j++) temp.state[i][j] = test[i][j];

    temp.encrypt(output);

    UC *b = (UC *) output;
    for (int i = 0; i < 16; i++) printf("%02x", b[i]);
    putchar('\n');

    AES dec;
    dec.initKeys(128, keys);
    for (UC i = 0; i < 4; i++)
        for (UC j = 0; j < 4; j++) dec.state[i][j] = b[i * 4 + j];

    dec.decrypt(output);
    for (int i = 0; i < 16; i++) printf("%02x", b[i]);
    putchar('\n');

}

void testAES192() {
    AES temp;
    keys[0] = 0x03020100;
    keys[1] = 0x07060504;
    keys[2] = 0x0b0a0908;
    keys[3] = 0x0f0e0d0c;
    keys[4] = 0x13121110;
    keys[5] = 0x17161514;
    temp.initKeys(192, keys);

    UC test[4][4] = {
        0xe5, 0x4b, 0x04, 0x09,
        0x9c, 0x6c, 0x16, 0xba,
        0x14, 0xa0, 0xe2, 0x5f,
        0x4f, 0xb6, 0x8d, 0xd4
    };

    for (UC i = 0; i < 4; i++)
        for (UC j = 0; j < 4; j++) temp.state[i][j] = test[i][j];

    temp.encrypt(output);

    UC *b = (UC *) output;
    for (int i = 0; i < 16; i++) printf("%02x", b[i]);
    putchar('\n');

    AES dec;
    dec.initKeys(192, keys);
    for (UC i = 0; i < 4; i++)
        for (UC j = 0; j < 4; j++) dec.state[i][j] = b[i * 4 + j];

    dec.decrypt(output);
    for (int i = 0; i < 16; i++) printf("%02x", b[i]);
    putchar('\n');

}

void testAES256() {
    AES temp;
    keys[0] = 0x03020100;
    keys[1] = 0x07060504;
    keys[2] = 0x0b0a0908;
    keys[3] = 0x0f0e0d0c;
    keys[4] = 0x13121110;
    keys[5] = 0x17161514;
    keys[6] = 0x1b1a1918;
    keys[7] = 0x1f1e1d1c;
    temp.initKeys(256, keys);

    UC test[4][4] = {
        0xe5, 0x4b, 0x04, 0x09,
        0x9c, 0x6c, 0x16, 0xba,
        0x14, 0xa0, 0xe2, 0x5f,
        0x4f, 0xb6, 0x8d, 0xd4
    };

    for (UC i = 0; i < 4; i++)
        for (UC j = 0; j < 4; j++) temp.state[i][j] = test[i][j];

    temp.encrypt(output);

    UC *b = (UC *) output;
    for (int i = 0; i < 16; i++) printf("%02x", b[i]);
    putchar('\n');

    AES dec;
    dec.initKeys(256, keys);
    for (UC i = 0; i < 4; i++)
        for (UC j = 0; j < 4; j++) dec.state[i][j] = b[i * 4 + j];

    dec.decrypt(output);
    for (int i = 0; i < 16; i++) printf("%02x", b[i]);
    putchar('\n');

}

void totalTest() {

}

int main() {
    srand(time(NULL));
    printf("AES encryption and decryption program\n");
    //testSbox();
    //testMult(0, 0);
    //testMatrix();
    //testCI();
    //testRConj();
    //testKeystream();
    testAES128();
    testAES192();
    testAES256();
    //testRand();
    testEncryptMessage(shortM, 128);
    testEncryptMessage(shortM, 192);
    testEncryptMessage(shortM, 256);

    testEncryptMessage(longM, 128);
    testEncryptMessage(longM, 192);
    testEncryptMessage(longM, 256);
    return 0;
}
