#include <stdio.h>
#define uint unsigned int

uint rotateLeft(uint x, int n)
{
    return  (x << n) | (x >> (32-n));
}

// block size: 512b = 64B = 16W
// W (80W long) is the 16W of work + scratch space (prepadded)
// H (5W long) is the current hash state
void sha1_block(uint *W, uint *H)
{
        uint A,B,C,D,E,K0,K1,K2,K3,temp; 
        int i;
    
        K0 = 0x5A827999;
        K1 = 0x6ED9EBA1;
        K2 = 0x8F1BBCDC;
        K3 = 0xCA62C1D6;

        A = H[0];
        B = H[1];
        C = H[2];
        D = H[3];
        E = H[4];

        for(i = 16; i < 80; i++)
        {
            W[i] = rotateLeft(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
        }

        for(i = 0; i < 20; i++)
        {
            temp = rotateLeft(A,5) + ((B & C) | ((~ B) & D)) + E + W[i] + K0;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for(i = 20; i < 40; i++)
        {
            temp = rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + K1;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for(i = 40; i < 60; i++)
        {
            temp = rotateLeft(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + K2;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for(i = 60; i < 80; i++)
        {
            temp = rotateLeft(A, 5) + (B ^ C ^ D)  + E + W[i] + K3;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        H[0] = (H[0] + A);
        H[1] = (H[1] + B);
        H[2] = (H[2] + C);
        H[3] = (H[3] + D);
        H[4] = (H[4] + E);
}

int main() {
    uint H[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

    uint W1[80] = { 0x30818702, 0x818100e4, 0xde5a35ef, 0xbbeb8a0e, 0x40b77785, 0xae595329, 0xe8760083, 0x4b00f6fe, 0x33585955, 0xad99d092, 0x643e52c2, 0x48573caa, 0x4df36f8c, 0x4e8b8402, 0x4b24f3ed, 0x21314983 };
    sha1_block(W1,H);

    uint W2[80] = { 0xf5fc0191, 0xfc7213db, 0x38adcd76, 0xdd1cef9e, 0x0c43b82a, 0x395ca629, 0x05c0d309, 0x83bd693a, 0x7a05264c, 0xae7655c7, 0x82b65caf, 0xb55ac962, 0x25476c93, 0x5b001156, 0x7603a433, 0xade9188f };
    sha1_block(W2,H);

    uint W3[80] = { 0x5a43e44c, 0x365de702, 0x01038000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000450 };
    sha1_block(W3,H);

    printf("%x %x %x %x %x\n",H[0],H[1],H[2],H[3],H[4]);
    return 0;
}

