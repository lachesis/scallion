#include <stdio.h>
#define uint unsigned int
#define uint8 unsigned char
#define uint16 unsigned short
#define uint32 unsigned int
#define uint64 unsigned long
#define int8 char
#define int16 short
#define int32 int
#define int64 long

uint rotateLeft(uint32 x, int32 n)
{
    return  (x << n) | (x >> (32-n));
}

// block size: 512b = 64B = 16W
// W (80W long) is the 16W of work + scratch space (prepadded)
// H (5W long) is the current hash state
void sha1_block(uint32 *W, uint32 *H)
{
        uint32 A,B,C,D,E,K0,K1,K2,K3,temp; 
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
void base32_encode(uint8 *dest, uint destlen, const uint8 *src, uint srclen)
{
  uint32 i, v, u;
  uint nbits = srclen * 8, bit;

  // replace these with sane assertions, or just drop them
  //tor_assert(srclen < SIZE_T_CEILING/8);
  //tor_assert((nbits%5) == 0); /* We need an even multiple of 5 bits. */
  //tor_assert((nbits/5)+1 <= destlen); /* We need enough space. */
  //tor_assert(destlen < SIZE_T_CEILING);

  for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
    /* set v to the 16-bit value starting at src[bits/8], 0-padded. */
    v = ((uint8)src[bit/8]) << 8;
    if (bit+5<nbits) v += (uint8)src[(bit/8)+1];
    /* set u to the 5-bit value at the bit'th bit of src. */
    u = (v >> (11-(bit%8))) & 0x1F;
    dest[i] = BASE32_CHARS[u];
  }
  dest[i] = '\0';
}

// find the exponent field in the der
// *exp_addr gets set to the start of the exp data in der
// *exp_len gets set to the number of data bytes allowed
void find_exp_in_der(char *der, int *exp_addr, int *exp_len, int *total_len)
{
    int idx = 0;
    int lenb = 0, len = 0;
    int i = 0;

    idx++; // skip sequence id (0x30)
    // skip sequence header length bytes
    lenb = 0;
    if((der[idx] & 0x80) == 0x80) {
        lenb = (der[idx] & 0x7F);
        len = 0;
        for(i=0; i<lenb; i++)
            len += (uint)(der[idx+i+1] & 0xFF) << (8*i);
    }
    else
        len = der[idx];

    *total_len = len+lenb+2; // report the total length of the DER including seq header

    idx += lenb + 1;
    // now we're at the start of the modulus
    idx++; // skip the INTEGER id (0x02)

    // find the modulus length
    lenb = 0;
    if((der[idx] & 0x80) == 0x80) {
        lenb = (der[idx] & 0x7F);
        len = 0;
        for(i=0; i<lenb; i++)
            len += (uint)(der[idx+i+1] & 0xFF) << (8*i);
    }
    else
        len = der[idx];

    idx += lenb+1; // skip the length bytes
    idx += len; // skip the modulus

    // now we're at the start of the exponent
    idx++; // skip the 0x02

    // find the exponent length
    lenb = 0;
    if((der[idx] & 0x80) == 0x80) {
        lenb = (der[idx] & 0x7F);
        len = 0;
        for(i=0; i<lenb; i++)
            len += (uint)(der[idx+i+1] & 0xFF) << (8*i);
    }
    else
        len = der[idx];
    idx += lenb + 1; // skip the length bytes

    // set the return values
    *exp_len = len;
    *exp_addr = idx;
}


// put the new exponent value into the pubkey der
void change_exp_in_der_robust(char *der, int derlen, unsigned long newexp)
{
    int bytes_needed = 0;
    int explen = 0, totlen = 0, exp_addr=0;
    long ltotlen;
    uint8 exp_bytes[8];
    int idx = 0;

    // find number of bytes needed for exp
    while(newexp != 0) {
        exp_bytes[bytes_needed] = newexp & 0xFF;
        newexp >>= 8;
        bytes_needed++;
    }

    // if the top bit of the number is set, we need to prepend 0x00
    if((exp_bytes[bytes_needed-1] & 0x80) == 0x80)
        exp_bytes[++bytes_needed] = 0;

    // get a pointer to the exp data field
    find_exp_in_der(der,&exp_addr,&explen,&totlen);
    
    printf("explen: %lld, bn: %lld\n",explen,bytes_needed);

    // resize if needed
    if(explen < bytes_needed) {
        // First increase the sequence length
        // NOTE: this does NOT recalculate - it just increments the byte
        // If the sequence is likely to be near 127 or n*256 bytes long, 
        // this will need to be revised
        idx++;
        if((der[idx] & 0x80) == 0x80)
            idx += (der[idx] & 0x7F); // move to the length byte
        der[idx] += (uint8)(bytes_needed - explen);

        // Now increase the exponent length
        // Same caveat as for seq length, although exp will never be that long
        der[exp_addr-1] = bytes_needed;
    }

    // Write the exp bytes (big endian)
    for(idx=0;idx<bytes_needed;idx++)
        der[exp_addr+bytes_needed-1-idx] = exp_bytes[idx];

    // Update the SHA1 padding value
    totlen += bytes_needed - explen;
    ltotlen = (long)totlen * 8; // length in bits
    for(idx=0;idx<8;idx++) { // we're done with idx so let's reuse it
        der[derlen-1-idx] = ltotlen & 0xFF;
        ltotlen >>= 8;
    }
}

// W is the hash work block
// chunk is the 0-based index of this chunk (for 1024 bit key, chunk = 2)
// exp_addr is the index in der where the exp data starts
// newexp is the new exponent to insert
void change_exp_in_W(uint32 *W, int chunk, int exp_addr, unsigned long newexp)
{
    int bytes_needed=0,i=0;
    uint8 exp_bytes[8];

    // find number of bytes needed for exp
    while(newexp != 0) {
        exp_bytes[bytes_needed] = newexp & 0xFF;
        newexp >>= 8;
        bytes_needed++;
    }

    // if the top bit of the number is set, we need to prepend 0x00
    if((exp_bytes[bytes_needed-1] & 0x80) == 0x80)
        exp_bytes[++bytes_needed] = 0;

    // each chunk is 64 bytes, so get the address in bytes into W
    exp_addr -= chunk * 64;

    // change the word
    int waddr, baddr;
    for(i=bytes_needed-1;i>=0;i--) {
        waddr = exp_addr / 4;
        baddr = 3 - exp_addr % 4;
        W[waddr] &= ~((uint32)((uint32)0x000000FF << 8*baddr));
        W[waddr] |= (uint32)(exp_bytes[i] << 8*baddr);
        exp_addr++;
    }
}

// Copy one chunk of the DER to W
// der must be padded already
// W must be 80 words long (for the hash func)
// chunk starts at zero
void copy_der_to_W(uint8 *der, uint32 *W, int chunk)
{
    int i,j;
    for(i=0;i<16;i++) { // i is the word we're copying into
        j = chunk*64 + i*4;
        W[i] = der[j+0]<<24 | der[j+1]<<16 | der[j+2]<<8 | der[j+3];
    }
}

void print_hash(uint32 *H)
{
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
}

int main() {
    uint32 H[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uint32 Hmid[5];
    uint32 W[80];
    int i,exp_addr,explen,totlen;
    uint8 der[192] = { 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xd5, 0xb9, 0x6f, 0xc5, 0x70, 0x8e, 0x5d, 0xe3, 0x57, 0xd0, 0x7e, 0xea, 0x3c, 0x05, 0x9d, 0xd0, 0x9c, 0xd1, 0xb8, 0xec, 0xe2, 0xcf, 0xbc, 0xdc, 0xaf,
                       0x98, 0x37, 0x7a, 0xf4, 0xb2, 0xae, 0x55, 0xcb, 0xda, 0xf2, 0x94, 0x1b, 0x8e, 0xe5, 0x51, 0x86, 0x25, 0xf1, 0xd7, 0xfa, 0xb4, 0x55, 0xf5, 0xc0, 0xa3, 0x25, 0xb9, 0xa3, 0x14, 0xdd, 0xdf, 0xdf,
                       0xa9, 0x56, 0xd5, 0x89, 0x9b, 0x4e, 0x42, 0x27, 0xbb, 0x38, 0x14, 0xc0, 0x40, 0x72, 0x16, 0x27, 0x6d, 0x85, 0x99, 0x26, 0xe8, 0xc6, 0x03, 0x5c, 0x50, 0x3d, 0xd9, 0x14, 0x2d, 0x27, 0xe7, 0x1a,
                       0x4c, 0x06, 0x5a, 0x4d, 0xec, 0x07, 0x74, 0x8f, 0x41, 0x11, 0x9d, 0x69, 0x97, 0x15, 0x2b, 0x83, 0x9d, 0x30, 0x2e, 0x15, 0x2b, 0x41, 0x6f, 0x5a, 0xe1, 0x65, 0x25, 0x15, 0x41, 0x07, 0x17, 0x95,
                       0xd3, 0xf0, 0xf5, 0x27, 0x81, 0xb1, 0x27, 0x02, 0x03, 0x01, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x60 };
    
    copy_der_to_W(der,W,0);
    sha1_block(W,H);

    copy_der_to_W(der,W,1);
    sha1_block(W,H);

    for(i=0;i<5;i++) Hmid[i] = H[i];

    copy_der_to_W(der,W,2);
    sha1_block(W,H);

    print_hash(H);

    find_exp_in_der(der,&exp_addr,&explen,&totlen);
    
    for(i=0;i<5;i++) H[i] = Hmid[i];
    
    change_exp_in_W(W,2,exp_addr,0x010003);
    printf("uint32 W[80] = { ");
    for(i=0;i<16;i++)
        printf("0x%08x, ",W[i]);
    printf("};\n");
    sha1_block(W,H);
    print_hash(H);

    for(i=0;i<5;i++) H[i] = Hmid[i];

    change_exp_in_der_robust(der,192,0x010003);
    printf("uint8 der[192] = { ");
    for(i=0;i<192;i++)
        printf("0x%02hhx, ",der[i]);
    printf("};\n");
    copy_der_to_W(der,W,2);
    printf("uint32 W[80] = { ");
    for(i=0;i<16;i++)
        printf("0x%08x, ",W[i]);
    printf("};\n");
    sha1_block(W,H);
    print_hash(H);

    return 0;
}


