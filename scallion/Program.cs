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

		static byte[] DerMaker(IEnumerable<BigNumber> ints)
		{
			return null;
		}

		static BigNumber stub_run_kernel(byte[] der)
		{
			return new BigNumber((uint)0x1000d); // new value of e
		}

        static void Main(string[] args)
        {
            foreach (var item in  OpenGLInfo.GetFullPlatformInfo())
	        {
                Console.WriteLine("Name:{0} Version:{1} Vendor:{2} Profile:{3}", item.Name, item.Version, item.Vendor, item.Profile);
	        }

            //RSA rsa = new RSA();
            //int KEYLEN = 1024;

			// Make the DER
			byte[] der = new byte[KEYLEN+100];
			unsafe // must be a better way to do this!
			{
				IntPtr hglob = Marshal.AllocHGlobal(der.Length);
				void* ptr = hglob.ToPointer();
				void** ptr2 = &ptr;

				Native.i2d_RSAPublicKey(rsa.Handle, (byte**)ptr2);

				Marshal.Copy(hglob,der,0,der.Length);
				Marshal.FreeHGlobal(hglob);
			}

			// RUN THE KERNEL - output: new value of e
			BigNumber e = stub_run_kernel(der);
			rsa.PublicExponent = e; // stick e back into the key

			// Check the key for sanity and recalculate Private exponent (d)
			{
				// Get some bignum parameters
				BigNumber p1, q1, gcd, lambda;
				p1 = rsa.SecretPrimeFactorP - 1;   // p-1
				q1 = rsa.SecretPrimeFactorQ - 1;   // q-1
				gcd = BigNumber.gcd(p1,q1);		   // gcd of (p-1)(q-1)
				lambda = BigNumber.lcm(p1,q1,gcd); // lcm of (p-1)(q-1)

				// Check for sanity
				if(BigNumber.gcd(lambda,e) != 1) // check if e is coprime to lambda(n)
					throw new Exception("Key not sane - e and lcm not coprime");
				if(!(rsa.PublicExponent < rsa.PublicModulus - 1))
					throw new Exception("Key not sane - not (e < n-1)");

				// Recalculate D and stick it in the key
				rsa.PrivateExponent = BigNumber.mod_inverse(rsa.PublicExponent,lambda);
				rsa.DmodP1 = BigNumber.mod(rsa.PrivateExponent,p1);
				rsa.DmodQ1 = BigNumber.mod(rsa.PrivateExponent,q1);
				rsa.IQmodP = BigNumber.mod_inverse(rsa.SecretPrimeFactorQ,rsa.SecretPrimeFactorP);

				// Ask OpenSSL if it's sane
				if(!rsa.Check())
					throw new Exception("Key not sane - openssl says so");
			}

			// Output the key in the right format
			Console.Write(rsa.PrivateKeyAsPEM);

			/*foreach(var item in der.Take (30))
				Console.Write(item.ToString("x") + " ");
			Console.WriteLine();*/

			// Kernel steps
			// 1. Copy global DER into local space (leave extra bytes)
			// 2. Increase exponent (using stride) in loop
			// 3. Hash with SHA1
			// 4. Get the Onion encoding of this hash
			// 5. Compare to pattern, if win, quit
			// Be able to update the exponent size
			// Watch out for endianness of exponent
        }
    }
}
