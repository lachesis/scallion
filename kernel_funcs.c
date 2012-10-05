// convert a hash result to the string format required for onion addresses
// note: onion addresses use only the first 80 bits of the hash result
void base32_encode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  unsigned int i, v, u;
  size_t nbits = srclen * 8, bit;

  // replace these with sane assertions, or just drop them
  tor_assert(srclen < SIZE_T_CEILING/8);
  tor_assert((nbits%5) == 0); /* We need an even multiple of 5 bits. */
  tor_assert((nbits/5)+1 <= destlen); /* We need enough space. */
  tor_assert(destlen < SIZE_T_CEILING);

  for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
    /* set v to the 16-bit value starting at src[bits/8], 0-padded. */
    v = ((uint8_t)src[bit/8]) << 8;
    if (bit+5<nbits) v += (uint8_t)src[(bit/8)+1];
    /* set u to the 5-bit value at the bit'th bit of src. */
    u = (v >> (11-(bit%8))) & 0x1F;
    dest[i] = BASE32_CHARS[u];
  }
  dest[i] = '\0';
}

// put the new exponent value into the pubkey der
void change_exp_in_der_robust(char *der, unsigned long newexp)
{
    int bytes_needed = 0;
    int explen = 0;
    char *exp_ptr;
    char exp_bytes[8];
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
    find_exp_in_der(der,exp_ptr,&explen);

    // resize if needed
    if(explen < bytes_needed) {
        // First increase the sequence length
        // NOTE: this does NOT recalculate - it just increments the byte
        // If the sequence is likely to be near 127 or n*256 bytes long, 
        // this will need to be revised
        idx++;
        if((der[idx] & 0x80) == 0x80)
            idx += (der[idx] & 0x7F); // move to the length byte
        der[idx] += bytes_needed - explen;

        // Now increase the exponent length
        // Same caveat as for seq length, although exp will never be that long
        *(exp_ptr-1) = bytes_needed;
    }

    // Write the exp bytes (big endian)
    for(idx=0;idx<bytes_needed;idx++)
        exp_ptr[bytes_needed-1-idx] = exp_bytes[idx];
}

// find the exponent field in the der
// exp_ptr gets set to the start of the exp data
// *exp_len gets set to the number of data bytes allowed
void find_exp_in_der(char *der, char *exp_ptr, int *exp_len)
{
    int idx = 0;
    int lenb = 0, len = 0;
    int i = 0;

    idx++; // skip sequence id (0x30)
    // skip sequence header length bytes
    if((der[idx] & 0x80) == 0x80)
        idx += (der[idx] & 0x7F) + 1;
    else
        idx++;

    // now we're at the start of the modulus
    idx++; // skip the INTEGER id (0x02)

    // find the modulus length
    lenb = 0;
    if((der[idx] & 0x80) == 0x80) {
        lenb = (der[idx] & 0x7F);
        len = 0;
        for(i=0; i<lenb; i++)
            len += der[idx+i+1] << (8*i);
    }
    else
        len = der[idx];

    idx += lenb + 1; // skip the length bytes
    idx += len; // skip the modulus

    // now we're at the start of the exponent
    idx++; // skip the 0x02

    // find the exponent length
    lenb = 0;
    if((der[idx] & 0x80) == 0x80) {
        lenb = (der[idx] & 0x7F);
        len = 0;
        for(i=0; i<lenb; i++)
            len += der[idx+i+1] << (8*i);
    }
    else
        len = der[idx];
    idx += lenb + 1; // skip the length bytes

    // set the return values
    *exp_len = len;
    exp_ptr = der + idx;
}
