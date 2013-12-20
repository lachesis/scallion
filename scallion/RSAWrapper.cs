using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
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
			Timestamp = (uint)(DateTime.UtcNow - new DateTime(1970,1,1,0,0,0)).TotalSeconds;
		}

		public uint Timestamp { get; set; }
		public RSA Rsa { get; private set; }
	
		// TODO: Fewer copies, cleaner code
		// REGION: GPG
		private byte[] BigNumberToMPI(BigNumber num)
		{
			byte[] mpi = new byte[num.Bytes + 2];
			mpi[0] = (byte)((num.Bits >> 8) & 0xFFu);
			mpi[1] = (byte)(num.Bits & 0xFFu);
			byte[] buf = new byte[num.Bytes];
			num.ToBytes(buf);
			Array.Copy(buf, 0, mpi, 2, num.Bytes);
			return mpi;
		}

		public byte[] GPG_v4Packet() {
			int _;
			return GPG_v4Packet(out _);
		}

		// TODO: Rename and refactor
		// This is a signature packet for generating the fingerprint
		public byte[] GPG_v4Packet(out int exp_index) {
			// Packet format: (all big-endian)
			//	1 byte:     0x99 (fingerprint packet)
			//  2 bytes:    length of version -> end
			//  X bytes: 	pubkey material
			byte[] buf = GPG_pubkey_packet(out exp_index);

			byte[] v4pkt = new byte[3 + buf.Length];
			int idx = 0;

			v4pkt[idx] = 0x99; // 0x99 to start
			idx++;

			v4pkt[idx] = (byte)((buf.Length >> 8) & 0xFFu); // high-order length byte
			idx++;

			v4pkt[idx] = (byte)(buf.Length & 0xFFu); // low-order length byte
			idx++;

			exp_index += idx;

			Array.Copy(buf, 0, v4pkt, idx, buf.Length);

			return v4pkt;
		}

		private byte[] GPG_pubkey_packet() {
			int _;
			return GPG_pubkey_packet(out _);
		}

		private byte[] GPG_pubkey_packet(out int exp_index) {
			// Packet format: (all big-endian)
			//  1 byte:     version (0x04)
			//  1 byte:     algorithm type (0x01 = RSA)
			//  4 bytes:    timestamp
			//  X bytes:    MPI of n
			//  X bytes:    MPI of e

			byte[] buf;
			byte[] v4pkt = new byte[6 + 2*2 + Rsa.PublicModulus.Bytes + Rsa.PublicExponent.Bytes];
			int idx = 0;

			v4pkt[idx] = 0x04; // version
			idx++;

			buf = new byte[4];
			((BigNumber)Timestamp).ToBytes(buf);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			v4pkt[idx] = 0x01; // algorithm - RSA
			idx++;

			buf = BigNumberToMPI(Rsa.PublicModulus);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			// Set the exponent index (out parameter) for later verification
			exp_index = idx + 2; // (2 bytes for MPI length)
			// KEEP THIS! Valuable for adding new key sizes (although 1024 * X bits seems to be 13)
			//Console.WriteLine("Exponent should start at byte {0} (byte {1} in final block)", exp_index, exp_index % 64);

			buf = BigNumberToMPI(Rsa.PublicExponent);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			return v4pkt;
		}

		/*// Annoyingly, a key must have a valid (signed) UID for GPG to import it
		// Yet more hoops to jump through.
		private IList<byte> GPG_signature_packet() {
			List<byte> data = new List<byte>();

			byte[] buf;

			data.Add(); // LENGTH
			data.Add(0x04); // Version
			data.Add(0x13); // Sig type (Positive certification of a User ID and Public Key packet)
			data.Add(0x01); // Pub alg (RSA)
			data.Add(0x08); // Hash alg (SHA256)
			data.Add(); // HASHED PACKET LENGTHS

			// Add timestamp
			data.Add(0x05); // Length (1 + 4)
			data.Add(0x02); // Type (creation time)
			buf = new byte[4];
			((BigNumber)Timestamp).ToBytes(buf); // TODO: 2038 bug (this assumes ((BigNumber)Timestamp).Bytes == 4)
			data.AddRange(buf);

			// Add keyid
			data.Add(0x09); // Length (1 + 8)
			data.Add(16);   // Type (issuer)
			buf = this.GPG_fingerprint;
			data.AddRange(buf.Skip(buf.Length - 8).Take(8));

			return data;
		}*/

		private byte[] GPG_privkey_packet() {
			// Packet format: (all big-endian)
			//  1 byte:     version (0x04)
			//  1 byte:     algorithm type (0x01 = RSA)
			//  4 bytes:    timestamp
			//  X bytes:    MPI of n
			//  X bytes:    MPI of e
			//  1 byte:		encryption state of private keys (0x00 = plaintext)
			//  X bytes:    MPI of d
			//  X bytes:    MPI of p
			//  X bytes:    MPI of q
			//  X bytes:    MPI of u
			//  2 bytes:    sum of all bytes in d-u, mod 65536
			byte[] buf;

			BigNumber IPmodQ = BigNumber.mod_inverse(Rsa.SecretPrimeFactorP, Rsa.SecretPrimeFactorQ);

			int len = 6 + 2*2 + Rsa.PublicModulus.Bytes + Rsa.PublicExponent.Bytes +
					  3 + 2*4 + Rsa.PrivateExponent.Bytes + Rsa.SecretPrimeFactorP.Bytes + Rsa.SecretPrimeFactorQ.Bytes + IPmodQ.Bytes;

			byte[] v4pkt = new byte[len];
			int idx = 0;

			v4pkt[idx] = 0x04; // version
			idx += 1;

			buf = new byte[4];
			((BigNumber)Timestamp).ToBytes(buf);
			Array.Copy(buf, 0, v4pkt, idx, 4);
			idx += 4;

			v4pkt[idx] = 0x01; // algorithm - RSA
			idx += 1;

			buf = BigNumberToMPI(Rsa.PublicModulus);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			buf = BigNumberToMPI(Rsa.PublicExponent);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			// If we stopped here, we'd have a v4 pubkey packet (with the wrong length and tag)

			v4pkt[idx] = 0x00; // not encrypted
			idx += 1;

			int checksum_start = idx;

			buf = BigNumberToMPI(Rsa.PrivateExponent);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			buf = BigNumberToMPI(Rsa.SecretPrimeFactorP);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			buf = BigNumberToMPI(Rsa.SecretPrimeFactorQ);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			buf = BigNumberToMPI(IPmodQ);
			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			// Calculate checksum
			ulong sum = 0;
			for (int i = checksum_start; i < idx; i++) {
				sum += v4pkt[i];				
			}
			sum = sum % 65536;
			buf = new byte[2];
			((BigNumber)sum).ToBytes(buf);

			Array.Copy(buf, 0, v4pkt, idx, buf.Length);
			idx += buf.Length;

			return v4pkt;
		}

		private byte[] Packetize(byte tag, byte[] data) {
			// Packet format: (all big-endian)
			//	1 byte:     header (0x80 | ((tag << 2) & 0b00111100) | (length_type & 0b11)) -> tag = 5 for privkey
			//  1-4 bytes:  packet length (of data)
			int len = data.Length;

			int lenlen = new BigNumber((uint)len).Bytes;
			byte[] buf = new byte[lenlen];
			new BigNumber((uint)len).ToBytes(buf);

			// Calculate length type
			byte length_type = 0;
			switch (lenlen) {
				case 1:
					length_type = 0;
					break;
				case 2:
					length_type = 1;
					break;
				case 3:
					// Zero-pad length
					byte[] temp = new byte[4];
					Array.Copy(buf, 0, temp, 1, 3);
					temp[0] = 0;
					buf = temp;
					length_type = 2;
					break;
				case 4:
					length_type = 2;
					break;
				default:
					throw new Exception("Invalid length.");
			}

			// Calclulate packet header
			byte header = (byte)(0x80 | ((tag << 2) & 0x3C) | (length_type & 0x03));

			byte[] outdata = new byte[len + 1 + lenlen];
			int idx = 0;

			outdata[idx] = header;
			idx++;

			Array.Copy(buf, 0, outdata, idx, buf.Length);
			idx += buf.Length;

			Array.Copy(data, 0, outdata, idx, data.Length);
			idx += data.Length;

			return outdata;
		}

		static IEnumerable<string> ChunksUpto(string str, int maxChunkSize) {
			for (int i = 0; i < str.Length; i += maxChunkSize) 
				yield return str.Substring(i, Math.Min(maxChunkSize, str.Length-i));
		}

		private string ascii_armor(byte[] input, string tag) {
			StringBuilder s = new StringBuilder();
			s.AppendLine("-----BEGIN " + tag + "-----");
			s.AppendLine("Version: Scallion");
			s.AppendLine();
			foreach (var str in ChunksUpto(Convert.ToBase64String(input), 78)) {
				s.AppendLine(str);
			}
			s.AppendLine("-----END " + tag + "-----");
			return s.ToString();
		}

		public string GPG_privkey_export {
			get {
				byte[] privkey = Packetize(5, GPG_privkey_packet());
				byte[] uid = Packetize(13, System.Text.UTF8Encoding.UTF8.GetBytes("Scallion UID (replace me)"));

				byte[] concat = new byte[privkey.Length + uid.Length];
				int idx = 0;

				Array.Copy(privkey, 0, concat, idx, privkey.Length);
				idx += privkey.Length;

				Array.Copy(uid, 0, concat, idx, uid.Length);
				idx += uid.Length;

				return ascii_armor(concat, "PGP PRIVATE KEY BLOCK");
			}
		}

		public byte[] GPG_fingerprint {
			get {
				var sha1 = new System.Security.Cryptography.SHA1Managed();
				return sha1.ComputeHash(this.GPG_v4Packet());
			}
		}

		public string GPG_fingerprint_string {
			get {
				return BitConverter.ToString(this.GPG_fingerprint).Replace("-","").ToLower();
			}
		}
		// END REGION: GPG

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


