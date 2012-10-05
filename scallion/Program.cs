using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OpenSSL.Crypto;
using System.Runtime.InteropServices;
using OpenSSL.Core;

namespace scallion
{
    class Program
    {
		static BigNumber stub_run_kernel(byte[] der)
		{
			return new BigNumber((uint)0x1000d); // new value of e
		}

		// put the new exponent value into the pubkey der
		public static void change_exp_in_der_robust(byte[] der, ulong newexp)
		{
		    int bytes_needed = 0;
		    int explen = 0;
		    int exp_addr = 0;
		    byte[] exp_bytes = new byte[8];
		    int idx = 0;

		    // find number of bytes needed for exp
		    while(newexp != 0) {
		        exp_bytes[bytes_needed] = (byte)(newexp&0xFF);
		        newexp >>= 8;
		        bytes_needed++;
		    }
		    
		    // if the top bit of the number is set, we need to prepend 0x00
		    if((exp_bytes[bytes_needed-1] & 0x80) == 0x80)
			{
				exp_bytes[bytes_needed+1] = 0;
				bytes_needed++;
			}

		    // get a pointer to the exp data field
		    find_exp_in_der(der,out exp_addr,out explen);

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
				der[exp_addr-1] = (byte)bytes_needed;
		    }

		    // Write the exp bytes (big endian)
		    for(idx=0;idx<bytes_needed;idx++)
		        der[exp_addr+bytes_needed-1-idx] = exp_bytes[idx];
		}

		// find the exponent field in the der
		// exp_ptr gets set to the start of the exp data
		// *exp_len gets set to the number of data bytes allowed
		public static void find_exp_in_der(byte[] der, out int exp_addr, out int exp_len)
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
		    exp_len = len;
		    exp_addr = idx;
		}

		static void ExpTwiddle(byte[] der, ulong exp)
		{
			change_exp_in_der_robust(der,exp);

			Console.Write("exponent: 0x{0:x8}  bytes: ",exp);
			foreach(byte b in der.Skip(3+4+1024/8))
				Console.Write("0x{0:x2} ",b);
			Console.WriteLine();

		}

		static void ExpTwiddleOSSL(RSAWrapper rsa, uint exp)
		{
			rsa.Rsa.PublicExponent = new BigNumber(exp);
			byte[] der = rsa.DER;
			Console.Write("exponent: 0x{0:x8}  bytes: ",exp);
			foreach(byte b in der.Skip(3+4+1024/8))
				Console.Write("0x{0:x2} ",b);
			Console.WriteLine();
		}

        static void Main(string[] args)
        {
            /*foreach (var item in OpenGLInfo.GetFullDeviceInfo())
            {
                System.IO.StringWriter writer = new System.IO.StringWriter();
                ObjectDumper.Write(item, 2, writer);
                Console.WriteLine(writer.ToString());
                Console.WriteLine();
            }
            Console.ReadKey();

            foreach (var item in  OpenGLInfo.GetFullPlatformInfo())
            {
                Console.WriteLine("Name:{0} Version:{1} Vendor:{2} Profile:{3}", item.Name, item.Version, item.Vendor, item.Profile);
            }*/

			RSAWrapper rsa = new RSAWrapper();
			rsa.GenerateKey(1024);

			byte[] der = new byte[][] { rsa.DER, new byte[10] }.SelectMany(i=>i).ToArray();
			ExpTwiddle(der,0x7F);
			ExpTwiddleOSSL(rsa,0x7F);
			ExpTwiddle(der,0x80);
			ExpTwiddleOSSL(rsa,0x80);
			ExpTwiddle(der,0x81);
			ExpTwiddleOSSL(rsa,0x81);
			ExpTwiddle(der,0xFADEAD);
			ExpTwiddleOSSL(rsa,0xFADEAD);

			/*{
				rsa.Rsa.PublicExponent = 0x7F;
				byte[] der = rsa.DER;
				Console.Write("exponent: 0x{0:x8}  bytes: ",rsa.Rsa.PublicExponent);
				foreach(byte b in der.Skip(3+4+1024/8))
					Console.Write("0x{0:x2} ",b);
				Console.WriteLine();
			}
			{
				rsa.Rsa.PublicExponent = 0x80;
				byte[] der = rsa.DER;
				Console.Write("exponent: 0x{0:x8}  bytes: ",rsa.Rsa.PublicExponent);
				foreach(byte b in der.Skip(3+4+1024/8))
					Console.Write("0x{0:x2} ",b);
				Console.WriteLine();
			}*/

			// twiddle the der

			/*for (int i = 0; i < 1024; i++) {			
				rsa.Rsa.PublicExponent += new BigNumber((uint)i*1024);
				byte[] der = rsa.DER;
				Console.Write("exponent: 0x{0:x8}  bytes: ",rsa.Rsa.PublicExponent);
				foreach(byte b in der.Skip(3+4+1024/8))
					Console.Write("0x{0:x2} ",b);
				Console.WriteLine();
			}*/
			/*
            // RUN THE KERNEL - output: new value of e
            BigNumber e = stub_run_kernel(rsa.DER);
            
			// Insert the new exponent (also checks sanity)
			rsa.ChangePublicExponent(e);

			// Output the onion address
			Console.WriteLine(rsa.OnionHash + ".onion");

            // Output the key
            Console.Write(rsa.Rsa.PrivateKeyAsPEM);
            */

            //// Kernel steps
            //// 1. Copy global DER into local space (leave extra bytes)
            //// 2. Increase exponent (using stride) in loop
            //// 3. Hash with SHA1
            //// 4. Get the Onion encoding of this hash
            //// 5. Compare to pattern, if win, quit
            //// Be able to update the exponent size
            //// Watch out for endianness of exponent
        }
    }
}
