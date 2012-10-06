using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Runtime.InteropServices;
using OpenSSL.Crypto;
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
		        der[idx] += (byte)(bytes_needed - explen);

		        // Now increase the exponent length
		        // Same caveat as for seq length, although exp will never be that long
				// Even more strongly, won't work if exp needs more than 1 length byte
				// Still, exp will never reach 127 bytes long, so not a problem
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

		/// <summary>
		/// Returns the DER length of the specified value.
		/// </summary>
		/// <param name='val'>
		/// Value.
		/// </param>
		static private int get_der_len(ulong val)
		{
			if(val == 0) return 1;
			ulong tmp = val;
			int len = 0;

			// Find the length of the value
			while(tmp != 0) {
				tmp >>= 8;
				len++;
			}

			// if the top bit of the number is set, we need to prepend 0x00
			if(((val >> 8*(len-1)) & 0x80) == 0x80)
				len++;

			return len;
		}


        static void Main(string[] args)
        {
			RSAWrapper rsa = new RSAWrapper();
			rsa.GenerateKey(1024); // Generate a key

			const ulong EXP_MIN = 0x10001;
			const ulong EXP_MAX = 0xFFFFFFFFFF;

			int num_exps = (get_der_len(EXP_MAX) - get_der_len(EXP_MIN) + 1);
			int cur_exp_num = 0; 
			uint[] LastWs = new uint[num_exps*16];
			uint[] Midstates = new uint[num_exps*5];
			int[] ExpIndexes = new int[num_exps];

			// Build DERs and calculate midstates for exponents of representitive lengths
			for (int i = get_der_len(EXP_MIN); i <= get_der_len(EXP_MAX); i++) {
				ulong exp = (ulong)0x01 << (int)((i-1)*8);

				// Set the exponent in the RSA key
				// NO SANITY CHECK - just for building a DER
				rsa.Rsa.PublicExponent = (BigNumber)exp; 

				// Get the DER
				byte[] der = rsa.DER;
				int exp_index = der.Length % 64 - i;

				// Put the DER into Ws
				SHA1 Sha1 = new SHA1();
				List<uint[]> Ws = Sha1.DataToPaddedBlocks(der);

				// Put all but the last block through the hash
				Ws.Take(Ws.Count-1).Select((t) => {
					Sha1.SHA1_Block(t);
					return t;
				}).ToArray();

				// Put the midstate, the last W block, and the byte index of the exponent into the CL buffers
				Sha1.H.CopyTo(Midstates,5*cur_exp_num);
				Ws.Last().Take(16).ToArray().CopyTo(LastWs,16*cur_exp_num);
				ExpIndexes[cur_exp_num] = exp_index; 

				// Increment the current exponent size
				cur_exp_num++;
			}

			//rsa.DER;

			//var v = new CLDeviceInfo(CLDeviceInfo.GetDeviceIds()[0]);
			//Console.WriteLine(v.MaxComputeUnits);

			//RSAWrapper rsa = new RSAWrapper();
			//rsa.GenerateKey(1024);
			RSAWrapper r2sa = new RSAWrapper("key.pem");

			{
				byte[] eder = rsa.DER;
				int midlength = 64-eder.Length%64-9;
				if(midlength < 0) midlength = 0;
				byte[] der = (new byte[][] { eder, new byte[] {0x80}, new byte[midlength], Mono.DataConverter.Pack("^L",new object[] { eder.Length*8 }) }).SelectMany(i=>i).ToArray();
				Console.Write ("uint8 der[{0}] = {{ ",der.Length);
				for (int j = 0; j < der.Length; j+=1)
					Console.Write("0x{0:x2}, ",der[j]);
				Console.WriteLine ("}};");
			}

			uint[] exps = { 3329, 8389889, 8396033, 2147484929 };
			string[] hash = { "byfmhvyb6ndhwqvt", "rbchafzx2so5rh7i", "n3y7nkhpllhc37xg", "joiqzbhcabjp4j6f" };
			for (int q = 0; q < 4; q++) {
				rsa.ChangePublicExponent(exps[q]);
				Console.WriteLine("exp: {0}, pred: {1}, act: {2}, equal? {3}",exps[q],hash[q],rsa.OnionHash,hash[q] == rsa.OnionHash);
			}

			rsa.ChangePublicExponent(3329);

			// Output the onion address
			Console.WriteLine(rsa.OnionHash + ".onion");

            // Output the key
            Console.Write(rsa.Rsa.PrivateKeyAsPEM);

			// output the der
			{
				byte[] eder = rsa.DER;
				int midlength = 64-eder.Length%64-9;
				if(midlength < 0) midlength = 0;
				byte[] der = (new byte[][] { eder, new byte[] {0x80}, new byte[midlength], Mono.DataConverter.Pack("^L",new object[] { eder.Length*8 }) }).SelectMany(i=>i).ToArray();
				Console.Write ("uint8 der[{0}] = {{ ",der.Length);
				for (int j = 0; j < der.Length; j+=1)
					Console.Write("0x{0:x2}, ",der[j]);
				Console.WriteLine ("}};");
			}

			//var sha1 = new System.Security.Cryptography.SHA1Managed();
			//Console.WriteLine(BitConverter.ToString(sha1.ComputeHash(eder)));
			                 


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
