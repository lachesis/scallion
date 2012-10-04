// Copyright (c) 2009 Ben Henderson
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using OpenSSL.Core;

namespace OpenSSL.SSL
{
	class SslCipher : Base, IStackable
	{
		#region SSL_CIPHER
		[StructLayout(LayoutKind.Sequential)]
		struct SSL_CIPHER
		{
			public int valid;
			public IntPtr name; // text name
			public uint id; // id, 4 bytes, first is version
			public uint algorithms; // what ciphers are used
			public uint algo_strength; // strength and export flags
			public uint algorithm2; // extra flags
			public int strength_bits; // number of bits really used
			public int alg_bits; // number of bits for algorithm
			public uint mask; // used for matching
			public uint mask_strength; // also used for matching
		}
		#endregion

		bool isInitialized = false;
		private SSL_CIPHER raw;
		private CipherAlgorithmType cipherAlgorithm = CipherAlgorithmType.None;
		private int cipherStrength = 0;
		private HashAlgorithmType hashAlgorithm = HashAlgorithmType.None;
		private ExchangeAlgorithmType keyExchangeAlgorithm = ExchangeAlgorithmType.None;
		private AuthenticationMethod authMethod = AuthenticationMethod.None;
		private int keyExchangeStrength = 0;
		private SslProtocols sslProtocol = SslProtocols.None;

		public SslCipher() :
			this(IntPtr.Zero, false)
		{
		}

		public SslCipher(IntPtr ptr, bool owner) :
			base(ptr, owner)
		{
			Initialize();
		}

		internal SslCipher(IStack stack, IntPtr ptr) :
			base(ptr, true)
		{
			Initialize();
		}

		/// <summary>
		/// Returns SSL_CIPHER_name()
		/// </summary>
		public string Name
		{
			get { return Native.SSL_CIPHER_name(this.ptr); }
		}

		/// <summary>
		/// Returns SSL_CIPHER_description()
		/// </summary>
		public string Description
		{
			get
			{
				byte[] buf = new byte[512];
				Native.SSL_CIPHER_description(this.ptr, buf, buf.Length);
				string ret = Encoding.ASCII.GetString(buf);
				return ret;
			}
		}

		/// <summary>
		/// Returns SSL_CIPHER_get_bits()
		/// </summary>
		public int Strength
		{
			get
			{
				Initialize();
				if (cipherStrength == 0)
				{
					int nAlgBits = 0;
					return Native.SSL_CIPHER_get_bits(this.Handle, out nAlgBits);
				}
				return cipherStrength;
			}
		}

		public const int SSL_EXPORT = 0x00000002;
		public const int SSL_EXP40 = 0x00000008;
		public const int SSL_EXP56 = 0x00000010;

		private bool IsExport(uint algo_strength)
		{
			return (algo_strength & SSL_EXPORT) > 0;
		}

		private int ExportPrivateKeyLength(uint algo_strength)
		{
			if ((algo_strength & SSL_EXP40) > 0)
			{
				return 512;
			}
			return 1024;
		}

		private int ExportKeyLength(uint algorithms, uint algo_strength)
		{
			if ((algo_strength & SSL_EXP40) > 0)
			{
				return 5;
			}
			else
			{
				if ((algorithms & SSL_ENC_MASK) == SSL_DES)
				{
					return 8;
				}
				return 7;
			}
		}

		public const int SSL_MKEY_MASK = 0x000000FF;
		public const int SSL_kRSA = 0x00000001; /* RSA key exchange */
		public const int SSL_kDHr = 0x00000002; /* DH cert RSA CA cert */
		public const int SSL_kDHd = 0x00000004; /* DH cert DSA CA cert */
		public const int SSL_kFZA = 0x00000008;
		public const int SSL_kEDH = 0x00000010; /* tmp DH key no DH cert */
		public const int SSL_kKRB5 = 0x00000020; /* Kerberos5 key exchange */
		public const int SSL_kECDH = 0x00000040; /* ECDH w/ long-term keys */
		public const int SSL_kECDHE = 0x00000080; /* ephemeral ECDH */
		public const int SSL_EDH = (SSL_kEDH | (SSL_AUTH_MASK ^ SSL_aNULL));

		public const int SSL_AUTH_MASK = 0x00007F00;
		public const int SSL_aRSA = 0x00000100; /* Authenticate with RSA */
		public const int SSL_aDSS = 0x00000200; /* Authenticate with DSS */
		public const int SSL_DSS = SSL_aDSS;
		public const int SSL_aFZA = 0x00000400;
		public const int SSL_aNULL = 0x00000800; /* no Authenticate, ADH */
		public const int SSL_aDH = 0x00001000; /* no Authenticate, ADH */
		public const int SSL_aKRB5 = 0x00002000; /* Authenticate with KRB5 */
		public const int SSL_aECDSA = 0x00004000; /* Authenticate with ECDSA */

		public const int SSL_NULL = (SSL_eNULL);
		public const int SSL_ADH = (SSL_kEDH | SSL_aNULL);
		public const int SSL_RSA = (SSL_kRSA | SSL_aRSA);
		public const int SSL_DH = (SSL_kDHr | SSL_kDHd | SSL_kEDH);
		public const int SSL_ECDH = (SSL_kECDH | SSL_kECDHE);
		public const int SSL_FZA = (SSL_aFZA | SSL_kFZA | SSL_eFZA);
		public const int SSL_KRB5 = (SSL_kKRB5 | SSL_aKRB5);

		public const int SSL_ENC_MASK = 0x1C3F8000;
		public const int SSL_DES = 0x00008000;
		public const int SSL_3DES = 0x00010000;
		public const int SSL_RC4 = 0x00020000;
		public const int SSL_RC2 = 0x00040000;
		public const int SSL_IDEA = 0x00080000;
		public const int SSL_eFZA = 0x00100000;
		public const int SSL_eNULL = 0x00200000;
		public const int SSL_AES = 0x04000000;
		public const int SSL_CAMELLIA = 0x08000000;
		public const int SSL_SEED = 0x10000000;

		public const int SSL_MAC_MASK = 0x00c00000;
		public const int SSL_MD5 = 0x00400000;
		public const int SSL_SHA1 = 0x00800000;
		public const int SSL_SHA = (SSL_SHA1);

		public const int SSL_SSL_MASK = 0x03000000;
		public const int SSL_SSLV2 = 0x01000000;
		public const int SSL_SSLV3 = 0x02000000;
		public const int SSL_TLSV1 = SSL_SSLV3;	/* for now */

		/* Flags for the SSL_CIPHER.algorithm2 field */
		public const int SSL2_CF_5_BYTE_ENC = 0x01;
		public const int SSL2_CF_8_BYTE_ENC = 0x02;

		private void Initialize()
		{
			if (this.ptr == IntPtr.Zero || isInitialized)
			{
				return;
			}

			isInitialized = true;

			// marshal the structure
			raw = (SSL_CIPHER)Marshal.PtrToStructure(ptr, typeof(SSL_CIPHER));
			// start picking the data out
			bool isExport = IsExport(raw.algo_strength);
			int privateKeyLength = ExportPrivateKeyLength(raw.algo_strength);
			int keyLength = ExportKeyLength(raw.algorithms, raw.algo_strength);

			// Get the SSL Protocol version
			if ((raw.algorithms & SSL_SSLV2) == SSL_SSLV2)
			{
				sslProtocol = SslProtocols.Ssl2;
			}
			else if ((raw.algorithms & SSL_SSLV3) == SSL_SSLV3)
			{
				sslProtocol = SslProtocols.Tls; // SSL3 & TLS are the same here...
			}

			// set the keyExchange strength
			keyExchangeStrength = privateKeyLength;

			// Get the Key Exchange cipher and strength
			switch (raw.algorithms & SSL_MKEY_MASK)
			{
				case SSL_kRSA:
					keyExchangeAlgorithm = ExchangeAlgorithmType.RsaKeyX;
					break;
				case SSL_kDHr:
				case SSL_kDHd:
				case SSL_kEDH:
					keyExchangeAlgorithm = ExchangeAlgorithmType.DiffieHellman;
					break;
				case SSL_kKRB5:         /* VRS */
				case SSL_KRB5:          /* VRS */
					keyExchangeAlgorithm = ExchangeAlgorithmType.Kerberos;
					break;
				case SSL_kFZA:
					keyExchangeAlgorithm = ExchangeAlgorithmType.Fortezza;
					break;
				case SSL_kECDH:
				case SSL_kECDHE:
					keyExchangeAlgorithm = ExchangeAlgorithmType.ECDiffieHellman;
					break;
			}

			// Get the authentication method
			switch (raw.algorithms & SSL_AUTH_MASK)
			{
				case SSL_aRSA:
					authMethod = AuthenticationMethod.Rsa;
					break;
				case SSL_aDSS:
					authMethod = AuthenticationMethod.Dss;
					break;
				case SSL_aDH:
					authMethod = AuthenticationMethod.DiffieHellman;
					break;
				case SSL_aKRB5:         /* VRS */
				case SSL_KRB5:          /* VRS */
					authMethod = AuthenticationMethod.Kerberos;
					break;
				case SSL_aFZA:
				case SSL_aNULL:
					authMethod = AuthenticationMethod.None;
					break;
				case SSL_aECDSA:
					authMethod = AuthenticationMethod.ECDsa;
					break;
			}
			// Get the symmetric encryption cipher info
			switch (raw.algorithms & SSL_ENC_MASK)
			{
				case SSL_DES:
					cipherAlgorithm = CipherAlgorithmType.Des;
					if (isExport && keyLength == 5)
					{
						cipherStrength = 40;
					}
					else
					{
						cipherStrength = 56;
					}
					break;
				case SSL_3DES:
					cipherAlgorithm = CipherAlgorithmType.TripleDes;
					cipherStrength = 168;
					break;
				case SSL_RC4:
					cipherAlgorithm = CipherAlgorithmType.Rc4;
					if (isExport)
					{
						if (keyLength == 5)
						{
							cipherStrength = 40;
						}
						else
						{
							cipherStrength = 56;
						}
					}
					else
					{
						if ((raw.algorithm2 & SSL2_CF_8_BYTE_ENC) == SSL2_CF_8_BYTE_ENC)
						{
							cipherStrength = 64;
						}
						else
						{
							cipherStrength = 128;
						}
					}
					break;
				case SSL_RC2:
					cipherAlgorithm = CipherAlgorithmType.Rc2;
					if (isExport)
					{
						if (keyLength == 5)
						{
							cipherStrength = 40;
						}
						else
						{
							cipherStrength = 56;
						}
					}
					else
					{
						cipherStrength = 128;
					}
					break;
				case SSL_IDEA:
					cipherAlgorithm = CipherAlgorithmType.Idea;
					cipherStrength = 128;
					break;
				case SSL_eFZA:
					cipherAlgorithm = CipherAlgorithmType.Fortezza;
					break;
				case SSL_eNULL:
					cipherAlgorithm = CipherAlgorithmType.None;
					break;
				case SSL_AES:
					switch (raw.strength_bits)
					{
						case 128: cipherAlgorithm = CipherAlgorithmType.Aes128; break;
						case 192: cipherAlgorithm = CipherAlgorithmType.Aes192; break;
						case 256: cipherAlgorithm = CipherAlgorithmType.Aes256; break;
					}
					break;
				case SSL_CAMELLIA:
					switch (raw.strength_bits)
					{
						case 128: cipherAlgorithm = CipherAlgorithmType.Camellia128; break;
						case 256: cipherAlgorithm = CipherAlgorithmType.Camellia256; break;
					}
					break;
				case SSL_SEED:
					cipherAlgorithm = CipherAlgorithmType.Seed;
					cipherStrength = 128;
					break;
			}
			// Get the MAC info
			switch (raw.algorithms & SSL_MAC_MASK)
			{
				case SSL_MD5:
					hashAlgorithm = HashAlgorithmType.Md5;
					break;
				case SSL_SHA1:
					hashAlgorithm = HashAlgorithmType.Sha1;
					break;
				default:
					hashAlgorithm = HashAlgorithmType.None;
					break;
			}
		}

		public CipherAlgorithmType CipherAlgorithm
		{
			get
			{
				Initialize();
				return cipherAlgorithm;
			}
		}

		public HashAlgorithmType HashAlgorithm
		{
			get
			{
				Initialize();
				return hashAlgorithm;
			}
		}

		public ExchangeAlgorithmType KeyExchangeAlgorithm
		{
			get
			{
				Initialize();
				return keyExchangeAlgorithm;
			}
		}

		public int KeyExchangeStrength
		{
			get
			{
				Initialize();
				return keyExchangeStrength;
			}
		}

		public SslProtocols SslProtocol
		{
			get
			{
				Initialize();
				return sslProtocol;
			}
		}

		public AuthenticationMethod AuthenticateionMethod
		{
			get
			{
				Initialize();
				return authMethod;
			}
		}

		protected override void OnDispose()
		{
			Native.OPENSSL_free(this.ptr);
		}
	}
}
