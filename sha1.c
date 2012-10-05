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

// convert a hash result to the string format required for onion addresses
// note: onion addresses use only the first 80 bits of the hash result
#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz234567"
void base32_encode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  unsigned int i, v, u;
  size_t nbits = srclen * 8, bit;

  // replace these with sane assertions, or just drop them
  //tor_assert(srclen < SIZE_T_CEILING/8);
  //tor_assert((nbits%5) == 0); /* We need an even multiple of 5 bits. */
  //tor_assert((nbits/5)+1 <= destlen); /* We need enough space. */
  //tor_assert(destlen < SIZE_T_CEILING);

  for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
    /* set v to the 16-bit value starting at src[bits/8], 0-padded. */
    v = ((unsigned char)src[bit/8]) << 8;
    if (bit+5<nbits) v += (unsigned char)src[(bit/8)+1];
    /* set u to the 5-bit value at the bit'th bit of src. */
    u = (v >> (11-(bit%8))) & 0x1F;
    dest[i] = BASE32_CHARS[u];
  }
  dest[i] = '\0';
}


int main() {
    uint H[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uint W1[80] = {0x30818902, 0x818100d5, 0xb96fc570, 0x8e5de357, 0xd07eea3c, 0x059dd09c, 0xd1b8ece2, 0xcfbcdcaf, 0x98377af4, 0xb2ae55cb, 0xdaf2941b, 0x8ee55186, 0x25f1d7fa, 0xb455f5c0, 0xa325b9a3, 0x14dddfdf };
    sha1_block(W1,H);

    uint W2[80] = {0xa956d589, 0x9b4e4227, 0xbb3814c0, 0x40721627, 0x6d859926, 0xe8c6035c, 0x503dd914, 0x2d27e71a, 0x4c065a4d, 0xec07748f, 0x41119d69, 0x97152b83, 0x9d302e15, 0x2b416f5a, 0xe1652515, 0x41071795 };
    sha1_block(W2,H);

    uint W3[80] = {0xd3f0f527, 0x81b12702, 0x03010001, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000460 };
    sha1_block(W3,H);

    printf("%x %x %x %x %x\n",H[0],H[1],H[2],H[3],H[4]);

    char Hc[10]; // first 10 bytes of H in big-endian format
    int i,b;
    for(i=0; i<20; i++)
        Hc[i] = (H[i/4]>>(8*(3-i%4)))&0xff;

    for(i=0; i<20; i++)
        printf("%hhx ",Hc[i]);
    printf("\n");

    char dest[40];
    base32_encode(dest,40,Hc,10);

    printf("%s\n",dest);
    return 0;
}


