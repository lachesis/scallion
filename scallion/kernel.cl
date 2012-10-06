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

__kernel void kernel(__const uint32* LastWs, __const uint32* Midstates, __const int32* ExpIndexes, __global uint64* Results, uint64 base_exp, uint8 len_start){
	uint64 exp;
	int bytes_needed = 0;
	uint8 index;
	uint8 exp_bytes;
	uint64 newexp;
	uint32 exp_index;
	int i;
	int waddr, baddr;

	uint32 W[80];
	uint32 H[5];

	exp = get_global_id(0) * 2 + base_exp;
	newexp = exp;

	// find number of bytes needed for exp
    while(newexp != 0) {
        exp_bytes[bytes_needed] = newexp & 0xFF;
        newexp >>= 8;
        bytes_needed++;
    }
    
    // if the top bit of the number is set, we need to prepend 0x00
    if((exp_bytes[bytes_needed-1] & 0x80) == 0x80)
        exp_bytes[bytes_needed++] = 0;

	// Load data into Private Crap
	index = exp_bytes - len_start;
	for(i=0; i<16; i++)
		W[i] = LastWs[index*16+i];
	for(i=0; i<5; i++)
		H[i] = Midstates[index*5+i];
	exp_index = ExpIndexes[index]
	
	// Load the exponent into the place where they live
	for(i=bytes_needed-1; i>=0; i--) {
        waddr = exp_addr / 4;
        baddr = 3 - exp_addr % 4;
        W[waddr] &= ~((uint32)((uint32)0x000000FF << 8*baddr));
        W[waddr] |= (uint32)(exp_bytes[i] << 8*baddr);
        exp_addr++;
    }
    
    // Take the last part of the hash
	sha1_block(W,H);
	
	Results[0] = H[0];
	Results[1] = H[1];
	Results[2] = H[2];
	Results[3] = H[3];
	Results[4] = H[4];
	
	Results[6] = exp;
}