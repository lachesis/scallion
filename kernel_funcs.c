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

    // find number of bytes needed for exp
    while(newexp != 0) {
        exp_bytes[bytes_needed] = newexp & 0xFF;
        newexp >>= 8;
        bytes_needed++;
    }

    // get a pointer to the exp data field
    find_exp_in_der(der,exp_ptr,&explen);

    // resize if needed
    if(explen < bytes_needed) {
        // TODO: resize the field, keeping exp_ptr correct
    }

    // write the bytes into exp_ptr
    // TODO: write this
    // keep in mind: endianness, 0x00 needed if first bit == 1
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
