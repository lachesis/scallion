using System;
using System.Text;
using System.Runtime.InteropServices;
using OpenSSL.Core;
using OpenSSL.Crypto;

namespace scallion
{
	public class RSAWrapper
	{
		public RSAWrapper()
		{
			Rsa = new RSA();
		}

		public RSAWrapper(string keyfn)
		{
			using(BIO b = BIO.File(keyfn,"r"))
				Rsa = RSA.FromPrivateKey(b);
		}

		/*static byte[] Der2Size(ulong size)
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
		}*/

		public void FromPrivateKeyPEM(string pem)
		{
			Rsa = RSA.FromPrivateKey(new BIO(pem));
		}

		public void GenerateKey(int size)
		{
			GenerateKey(size,3);
		}

		public void GenerateKey(int size, BigNumber exponent)
		{
			Rsa.GenerateKeys(size,exponent,null,null);
		}

		public RSA Rsa { get; private set; }

		public byte[] DER {
			get {
				byte[] der;
				int buf_size = Rsa.Size + 100;
				int size = 0;
				unsafe // must be a better way to do this!
	            {
	                IntPtr hglob = Marshal.AllocHGlobal(buf_size);
	                void* ptr = hglob.ToPointer();
	                void** ptr2 = &ptr;

	                size = Native.i2d_RSAPublicKey(Rsa.Handle, (byte**)ptr2);
					if(size > buf_size)
						throw new IndexOutOfRangeException("DER was too large!");

					der = new byte[size];
	                Marshal.Copy(hglob,der,0,size);
	                Marshal.FreeHGlobal(hglob);
	            }
				return der;
			}
		}

		private byte[] get_der_hash()
		{
			var sha1 = new System.Security.Cryptography.SHA1Managed();
			return sha1.ComputeHash(this.DER);
			//return tobase32str(hash);
		}

		public string OnionHash
		{
			get {
				return tobase32str(this.get_der_hash(),10);
			}
		}

		public bool HasPrivateKey
		{
			get {
				return Rsa.SecretPrimeFactorP.Handle != IntPtr.Zero && Rsa.SecretPrimeFactorQ.Handle != IntPtr.Zero;
			}
		}

		public void ChangePublicExponent(BigNumber e)
		{
			Rsa.PublicExponent = e;

			if (HasPrivateKey) {
				// Get some bignum parameters
	            BigNumber p1, q1, gcd, lambda;
	            p1 = Rsa.SecretPrimeFactorP - 1;   // p-1
	            q1 = Rsa.SecretPrimeFactorQ - 1;   // q-1
	            gcd = BigNumber.gcd(p1,q1);		   // gcd of (p-1)(q-1)
	            lambda = BigNumber.lcm(p1,q1,gcd); // lcm of (p-1)(q-1)

			    // Recalculate D and stick it in the key
	            Rsa.PrivateExponent = BigNumber.mod_inverse(Rsa.PublicExponent,lambda);
	            Rsa.DmodP1 = BigNumber.mod(Rsa.PrivateExponent,p1);
	            Rsa.DmodQ1 = BigNumber.mod(Rsa.PrivateExponent,q1);
	            Rsa.IQmodP = BigNumber.mod_inverse(Rsa.SecretPrimeFactorQ,Rsa.SecretPrimeFactorP);

				CheckSanity();
			}
		}

		public void CheckSanity()
		{
			if (!HasPrivateKey) {
				throw new Exception("Key has no private key components.");
			}

            // Get some bignum parameters
            BigNumber p1, q1, gcd, lambda;
            p1 = Rsa.SecretPrimeFactorP - 1;   // p-1
            q1 = Rsa.SecretPrimeFactorQ - 1;   // q-1
            gcd = BigNumber.gcd(p1,q1);		   // gcd of (p-1)(q-1)
            lambda = BigNumber.lcm(p1,q1,gcd); // lcm of (p-1)(q-1)

            // Check for sanity
            if(BigNumber.gcd(lambda,Rsa.PublicExponent) != 1) // check if e is coprime to lambda(n)
                throw new Exception("Key not sane - e and lcm not coprime");
            if(!(Rsa.PublicExponent < Rsa.PublicModulus - 1))
                throw new Exception("Key not sane - not (e < n-1)");

            // Ask OpenSSL if it's sane
            if(!Rsa.Check())
                throw new Exception("Key not sane - openssl says so");
		}

		/*//------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---
		public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
		{
			byte[] MODULUS, E, D, P, Q, DP, DQ, IQ ;

			// ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
			MemoryStream  mem = new MemoryStream(privkey) ;
			BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
			byte bt = 0;
			ushort twobytes = 0;
			int elems = 0;
			try {
				twobytes = binr.ReadUInt16();
				if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
					binr.ReadByte();        //advance 1 byte
				else if (twobytes == 0x8230)
					binr.ReadInt16();       //advance 2 bytes
				else
					return null;

				twobytes = binr.ReadUInt16();
				if (twobytes != 0x0102) //version number
					return null;
				bt = binr.ReadByte();
				if (bt !=0x00)
					return null;


				//------  all private key components are Integer sequences ----
				elems = GetIntegerSize(binr);
				MODULUS = binr.ReadBytes(elems);

				elems = GetIntegerSize(binr);
				E = binr.ReadBytes(elems) ;

				elems = GetIntegerSize(binr);
				D = binr.ReadBytes(elems) ;

				elems = GetIntegerSize(binr);
				P = binr.ReadBytes(elems) ;

				elems = GetIntegerSize(binr);
				Q = binr.ReadBytes(elems) ;

				elems = GetIntegerSize(binr);
				DP = binr.ReadBytes(elems) ;

				elems = GetIntegerSize(binr);
				DQ = binr.ReadBytes(elems) ;

				elems = GetIntegerSize(binr);
				IQ = binr.ReadBytes(elems) ;

				Console.WriteLine("showing components ..");
				if (verbose) {
					showBytes("\nModulus", MODULUS) ;
					showBytes("\nExponent", E);
					showBytes("\nD", D);
					showBytes("\nP", P);
					showBytes("\nQ", Q);
					showBytes("\nDP", DP);
					showBytes("\nDQ", DQ);
					showBytes("\nIQ", IQ);
				}


				// ------- create RSACryptoServiceProvider instance and initialize with public key -----
				RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
				RSAParameters RSAparams = new RSAParameters();
				RSAparams.Modulus =MODULUS;
				RSAparams.Exponent = E;
				RSAparams.D = D;
				RSAparams.P = P;
				RSAparams.Q = Q;
				RSAparams.DP = DP;
				RSAparams.DQ = DQ;
				RSAparams.InverseQ = IQ;
				RSA.ImportParameters(RSAparams);
				return RSA;
			}
			catch (Exception) {
				return null;
			}
			finally {
				binr.Close();
			}
		}*/

		public static string tobase32str(byte[] src, int len)
		{
			const string BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567";
			int i, v, u, bit;
			int nbits = len * 8;

			StringBuilder sb = new StringBuilder();

/*			tor_assert(srclen < SIZE_T_CEILING/8);
			tor_assert((nbits%5) == 0); /* We need an even multiple of 5 bits. * /
			tor_assert((nbits/5)+1 <= destlen); /* We need enough space. * /
			tor_assert(destlen < SIZE_T_CEILING);*/

			for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
				/* set v to the 16-bit value starting at src[bits/8], 0-padded. */
				v = ((byte)src[bit/8]) << 8;
				if (bit+5<nbits) 
					v += (byte)src[(bit/8)+1];
				/* set u to the 5-bit value at the bit'th bit of src. */
				u = (v >> (11-(bit%8))) & 0x1F;
				sb.Append(BASE32_CHARS[u]);
			}
			return sb.ToString();
		}
	}
}

