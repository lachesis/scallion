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

            // RUN THE KERNEL - output: new value of e
            BigNumber e = stub_run_kernel(rsa.DER);
            
			// Insert the new exponent (also checks sanity)
			rsa.ChangePublicExponent(e);

			// Output the onion address
			Console.WriteLine(rsa.OnionHash + ".onion");

            // Output the key
            Console.Write(rsa.Rsa.PrivateKeyAsPEM);

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
