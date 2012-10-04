using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OpenSSL.Crypto;
using System.Runtime.InteropServices;

namespace scallion
{
    class Program
    {
		static byte[] Der2Size(ulong size)
		{
			if(size < 128)
				return new byte[] { (byte)((byte)0x00 | (byte)size) };
			else
			{
				byte[] tarr = Mono.DataConverter.Pack("^L", new object[] { size });
				byte[] sizes = tarr.SkipWhile(i=>i==0).ToArray();
				byte[] head = new byte[] { (byte)((byte)0x80 | (byte)sizes.Length) };

				return (new byte[][] { head, sizes }).SelectMany(i=>i).ToArray();
			}
		}

		static byte[] Int2DerBytes(OpenSSL.Core.BigNumber val, int val_min_size=0)
		{
			byte[] valb = new byte[Math.Max(val.Bytes,val_min_size)];
			val.ToBytes(valb);

			if ((valb[0] & 0x80) == 0x80)
				return (new byte[][] { new byte[] { 0x02 }, Der2Size((ulong)(val.Bytes+1)), new byte[] { 0x00 }, valb }).SelectMany(i=>i).ToArray();
			else
				return (new byte[][] { new byte[] { 0x02 }, Der2Size((ulong)val.Bytes), valb }).SelectMany(i=>i).ToArray();
		}

        static void Main(string[] args)
        {
            foreach (var item in  OpenGLInfo.GetFullPlatformInfo())
	        {
                Console.WriteLine("Name:{0} Version:{1} Vendor:{2} Profile:{3}", item.Name, item.Version, item.Vendor, item.Profile);
	        }

            //RSA rsa = new RSA();
            //int KEYLEN = 1024;

            //// Generate a key
            //rsa.GenerateKeys(KEYLEN,3,null,null);

            //// Make the der
            //byte[] mod_der = Int2DerBytes(rsa.PublicModulus);
            //byte[] exp_der = Int2DerBytes(rsa.PublicExponent, 3);
            //byte[] der = (new byte[][] { new byte[] { 0x30 }, Der2Size((ulong)(mod_der.Length + exp_der.Length)), mod_der, exp_der }).SelectMany(i=>i).ToArray();

            //foreach(var item in der.Take (30))
            //    Console.Write(item.ToString("x") + " ");
            //Console.WriteLine();

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
