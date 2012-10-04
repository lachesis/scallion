// Copyright (c) 2006-2010 Frank Laub
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
using OpenSSL.Crypto;

namespace OpenSSL.X509
{
	/// <summary>
	/// Wraps the X509 object
	/// </summary>
	public class X509Certificate : BaseCopyableRef<X509Certificate>, IComparable<X509Certificate>, IStackable
	{
		#region Initialization
		internal X509Certificate(IStack stack, IntPtr ptr)
			: base(ptr, true)
		{ }

		internal X509Certificate(IntPtr ptr, bool owner)
			: base(ptr, owner)
		{ }

		/// <summary>
		/// Calls X509_new()
		/// </summary>
		public X509Certificate()
			: base(Native.ExpectNonNull(Native.X509_new()), true)
		{ }

		/// <summary>
		/// Calls PEM_read_bio_X509()
		/// </summary>
		/// <param name="bio"></param>
		public X509Certificate(BIO bio)
			: base(Native.ExpectNonNull(Native.PEM_read_bio_X509(bio.Handle, IntPtr.Zero, null, IntPtr.Zero)), true)
		{ }

		/// <summary>
		/// Factory method that returns a X509 using d2i_X509_bio()
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static X509Certificate FromDER(BIO bio)
		{
			IntPtr pX509 = IntPtr.Zero;
			IntPtr ptr = Native.ExpectNonNull(Native.d2i_X509_bio(bio.Handle, ref pX509));
			return new X509Certificate(ptr, true);
		}

		/// <summary>
		/// Factory method to create a X509Certificate from a PKCS7 encoded in PEM
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static X509Certificate FromPKCS7_PEM(BIO bio)
		{
			PKCS7 pkcs7 = PKCS7.FromPEM(bio);
			X509Chain chain = pkcs7.Certificates;
			if (chain != null && chain.Count > 0)
			{
				return new X509Certificate(chain[0].Handle, false);
			}
			else
			{
				throw new OpenSslException();
			}
		}

		/// <summary>
		/// Factory method to create a X509Certificate from a PKCS7 encoded in DER
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static X509Certificate FromPKCS7_DER(BIO bio)
		{
			PKCS7 pkcs7 = PKCS7.FromDER(bio);
			X509Chain chain = pkcs7.Certificates;
			if (chain != null && chain.Count > 0)
			{
				return new X509Certificate(chain[0].Handle, false);
			}
			return null;
		}

		/// <summary>
		/// Factory method to create a X509Certificate from a PKCS12
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public static X509Certificate FromPKCS12(BIO bio, string password)
		{
			using (PKCS12 p12 = new PKCS12(bio, password))
			{
				return p12.Certificate;
			}
		}

		/// <summary>
		/// Creates a new X509 certificate
		/// </summary>
		/// <param name="serial"></param>
		/// <param name="subject"></param>
		/// <param name="issuer"></param>
		/// <param name="pubkey"></param>
		/// <param name="start"></param>
		/// <param name="end"></param>
		public X509Certificate(
			int serial,
			X509Name subject,
			X509Name issuer,
			CryptoKey pubkey,
			DateTime start,
			DateTime end)
			: this()
		{
			this.Version = 2;
			this.SerialNumber = serial;
			this.Subject = subject;
			this.Issuer = issuer;
			this.PublicKey = pubkey;
			this.NotBefore = start;
			this.NotAfter = end;
		}

		#endregion

		#region Raw Structures

		#region X509_VAL
		[StructLayout(LayoutKind.Sequential)]
		private struct X509_VAL
		{
			public IntPtr notBefore;
			public IntPtr notAfter;
		}
		#endregion

		#region X509_CINF
		[StructLayout(LayoutKind.Sequential)]
		private struct X509_CINF
		{
			public IntPtr version;
			public IntPtr serialNumber;
			public IntPtr signature;
			public IntPtr issuer;
			public IntPtr validity;
			public IntPtr subject;
			public IntPtr key;
			public IntPtr issuerUID;
			public IntPtr subjectUID;
			public IntPtr extensions;
		}
		#endregion

		#region X509
		[StructLayout(LayoutKind.Sequential)]
		private struct X509
		{
			public IntPtr cert_info;
			public IntPtr sig_alg;
			public IntPtr signature;
			public int valid;
			public int references;
			public IntPtr name;
			#region CRYPTO_EX_DATA ex_data
			public IntPtr ex_data_sk;
			public int ex_data_dummy;
			#endregion
			public int ex_pathlen;
			public int ex_pcpathlen;
			public uint ex_flags;
			public uint ex_kusage;
			public uint ex_xkusage;
			public uint ex_nscert;
			public IntPtr skid;
			public IntPtr akid;
			public IntPtr policy_cache;
			public IntPtr rfc3779_addr;
			public IntPtr rfc3779_asid;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.SHA_DIGEST_LENGTH)]
			public byte[] sha1_hash;
			public IntPtr aux;
		}
		#endregion

		#endregion

		#region Properties
		private X509 Raw
		{
			get { return (X509)Marshal.PtrToStructure(this.ptr, typeof(X509)); }
		}

		private X509_CINF RawCertInfo
		{
			get { return (X509_CINF)Marshal.PtrToStructure(this.Raw.cert_info, typeof(X509_CINF)); }
		}

		private X509_VAL RawValidity
		{
			get { return (X509_VAL)Marshal.PtrToStructure(this.RawCertInfo.validity, typeof(X509_VAL)); }
		}

		/// <summary>
		/// Uses X509_get_subject_name() and X509_set_issuer_name()
		/// </summary>
		public X509Name Subject
		{
			get
			{
				// Get the native pointer for the subject name
				IntPtr name_ptr = Native.ExpectNonNull(Native.X509_get_subject_name(this.ptr));
				X509Name ret = new X509Name(name_ptr, true);
				// Duplicate the native pointer, as the X509_get_subject_name returns a pointer
				// that is owned by the X509 object
				ret.AddRef();
				return ret;
			}
			set { Native.ExpectSuccess(Native.X509_set_subject_name(this.ptr, value.Handle)); }
		}

		/// <summary>
		/// Uses X509_get_issuer_name() and X509_set_issuer_name()
		/// </summary>
		public X509Name Issuer
		{
			get 
			{
				IntPtr name_ptr = Native.ExpectNonNull(Native.X509_get_issuer_name(this.ptr));
				X509Name name = new X509Name(name_ptr, true);
				name.AddRef();
				return name;
			}
			set { Native.ExpectSuccess(Native.X509_set_issuer_name(this.ptr, value.Handle)); }
		}

		/// <summary>
		/// Uses X509_get_serialNumber() and X509_set_serialNumber()
		/// </summary>
		public int SerialNumber
		{
			get { return Asn1Integer.ToInt32(Native.X509_get_serialNumber(this.ptr)); }
			set
			{
				using (Asn1Integer asnInt = new Asn1Integer(value))
				{
					Native.ExpectSuccess(Native.X509_set_serialNumber(this.ptr, asnInt.Handle));
				}
			}
		}

		/// <summary>
		/// Uses the notBefore field and X509_set_notBefore()
		/// </summary>
		public DateTime NotBefore
		{
			get { return Asn1DateTime.ToDateTime(this.RawValidity.notBefore); }
			set
			{
				using (Asn1DateTime asnDateTime = new Asn1DateTime(value))
				{
					Native.ExpectSuccess(Native.X509_set_notBefore(this.ptr, asnDateTime.Handle));
				}
			}
		}

		/// <summary>
		/// Uses the notAfter field and X509_set_notAfter()
		/// </summary>
		public DateTime NotAfter
		{
			get { return Asn1DateTime.ToDateTime(this.RawValidity.notAfter); }
			set
			{
				using (Asn1DateTime asnDateTime = new Asn1DateTime(value))
				{
					Native.ExpectSuccess(Native.X509_set_notAfter(this.ptr, asnDateTime.Handle));
				}
			}
		}

		/// <summary>
		/// Uses the version field and X509_set_version()
		/// </summary>
		public int Version
		{
			get { return Native.ASN1_INTEGER_get(this.RawCertInfo.version); }
			set { Native.ExpectSuccess(Native.X509_set_version(this.ptr, value)); }
		}

		/// <summary>
		/// Uses X509_get_pubkey() and X509_set_pubkey()
		/// </summary>
		public CryptoKey PublicKey
		{
			get 
			{
				// X509_get_pubkey() will increment the refcount internally
				IntPtr key_ptr = Native.ExpectNonNull(Native.X509_get_pubkey(this.ptr));
				return new CryptoKey(key_ptr, true);
			}
			set { Native.ExpectSuccess(Native.X509_set_pubkey(this.ptr, value.Handle)); }
		}

		/// <summary>
		/// Returns whether or not a Private Key is attached to this Certificate
		/// </summary>
		public bool HasPrivateKey
		{
			get { return privateKey != null; }
		}

		/// <summary>
		/// Gets and Sets the Private Key for this Certificate.
		/// The Private Key MUST match the Public Key.
		/// </summary>
		public CryptoKey PrivateKey
		{
			get { return privateKey.CopyRef(); }
			set
			{
				if (CheckPrivateKey(value))
				{
					privateKey = value.CopyRef();
				}
				else
				{
					throw new ArgumentException("Private key doesn't correspond to the this certificate");
				}
			}
		}

		/// <summary>
		/// Returns the PEM formatted string of this object
		/// </summary>
		public string PEM
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
					this.Write(bio);
					return bio.ReadString();
				}
			}
		}

		/// <summary>
		/// Returns the DER formatted byte array for this object
		/// </summary>
		public byte[] DER {
			get {
				using (BIO bio = BIO.MemoryBuffer()) {
					this.Write_DER(bio);
					return bio.ReadBytes((int)bio.NumberWritten).Array;
				}
			}
		}
		#endregion

		#region Methods
		/// <summary>
		/// Calls X509_sign()
		/// </summary>
		/// <param name="pkey"></param>
		/// <param name="digest"></param>
		public void Sign(CryptoKey pkey, MessageDigest digest)
		{
			if (Native.X509_sign(this.ptr, pkey.Handle, digest.Handle) == 0)
				throw new OpenSslException();
		}

		/// <summary>
		/// Returns X509_check_private_key()
		/// </summary>
		/// <param name="pkey"></param>
		/// <returns></returns>
		public bool CheckPrivateKey(CryptoKey pkey)
		{
			return Native.X509_check_private_key(this.ptr, pkey.Handle) == 1;
		}

		/// <summary>
		/// Returns X509_check_trust()
		/// </summary>
		/// <param name="id"></param>
		/// <param name="flags"></param>
		/// <returns></returns>
		public bool CheckTrust(int id, int flags)
		{
			return Native.X509_check_trust(this.ptr, id, flags) == 1;
		}

		/// <summary>
		/// Returns X509_verify()
		/// </summary>
		/// <param name="pkey"></param>
		/// <returns></returns>
		public bool Verify(CryptoKey pkey)
		{
			int ret = Native.X509_verify(this.ptr, pkey.Handle);
			if (ret < 0)
				throw new OpenSslException();
			return ret == 1;
		}

		/// <summary>
		/// Returns X509_digest()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public ArraySegment<byte> Digest(IntPtr type, byte[] digest)
		{
			uint len = (uint)digest.Length;
			Native.ExpectSuccess(Native.X509_digest(this.ptr, type, digest, ref len));
			return new ArraySegment<byte>(digest, 0, (int)len);
		}

		/// <summary>
		/// Returns X509_pubkey_digest()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public ArraySegment<byte> DigestPublicKey(IntPtr type, byte[] digest)
		{
			uint len = (uint)digest.Length;
			Native.ExpectSuccess(Native.X509_pubkey_digest(this.ptr, type, digest, ref len));
			return new ArraySegment<byte>(digest, 0, (int)len);
		}

		/// <summary>
		/// Calls PEM_write_bio_X509()
		/// </summary>
		/// <param name="bio"></param>
		public void Write(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_X509(bio.Handle, this.ptr));
		}

		/// <summary>
		/// Calls i2d_X509_bio()
		/// </summary>
		/// <param name="bio"></param>
		public void Write_DER(BIO bio) {
			Native.ExpectSuccess(Native.i2d_X509_bio(bio.Handle, this.ptr));
		}

		/// <summary>
		/// Calls X509_print()
		/// </summary>
		/// <param name="bio"></param>
		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.X509_print(bio.Handle, this.ptr));
		}

		/// <summary>
		/// Converts a X509 into a request using X509_to_X509_REQ()
		/// </summary>
		/// <param name="pkey"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public X509Request CreateRequest(CryptoKey pkey, MessageDigest digest)
		{
			return new X509Request(Native.ExpectNonNull(Native.X509_to_X509_REQ(this.ptr, pkey.Handle, digest.Handle)), true);
		}

		/// <summary>
		/// Calls X509_add_ext()
		/// </summary>
		/// <param name="ext"></param>
		public void AddExtension(X509Extension ext)
		{
			Native.ExpectSuccess(Native.X509_add_ext(this.ptr, ext.Handle, -1));
		}

		/// <summary>
		/// Calls X509_add1_ext_i2d()
		/// </summary>
		/// <param name="name"></param>
		/// <param name="value"></param>
		/// <param name="crit"></param>
		/// <param name="flags"></param>
		public void AddExtension(string name, byte[] value, int crit, uint flags)
		{
			Native.ExpectSuccess(Native.X509_add1_ext_i2d(this.ptr, Native.TextToNID(name), value, crit, flags));
		}

		/// <summary>
		/// 
		/// </summary>
		public Core.Stack<X509Extension> Extensions
		{
			get
			{
				if (RawCertInfo.extensions != IntPtr.Zero)
				{
					return new Core.Stack<X509Extension>(RawCertInfo.extensions, false);
				}
				return null;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sk_ext"></param>
		public void AddExtensions(Core.Stack<X509Extension> sk_ext)
		{
			foreach (X509Extension ext in sk_ext)
			{
				AddExtension(ext);
			}
		}

		#endregion

		#region Overrides
		/// <summary>
		/// Calls X509_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.X509_free(this.ptr);
			if (privateKey != null)
			{
				privateKey.Dispose();
				privateKey = null;
			}
		}

		/// <summary>
		/// Compares X509Certificate
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public override bool Equals(object obj)
		{
			X509Certificate rhs = obj as X509Certificate;
			if (rhs == null)
				return false;
			return this.CompareTo(rhs) == 0;
		}

		/// <summary>
		/// Returns the hash code of the issuer's oneline xor'd with the serial number
		/// </summary>
		/// <returns></returns>
		public override int GetHashCode()
		{
			return this.Issuer.OneLine.GetHashCode() ^ this.SerialNumber;
		}

		internal override CryptoLockTypes LockType
		{
			get { return CryptoLockTypes.CRYPTO_LOCK_X509; }
		}

		internal override Type RawReferenceType
		{
			get { return typeof(X509); }
		}

		#endregion

		#region IComparable Members

		/// <summary>
		/// Returns X509_cmp()
		/// </summary>
		/// <param name="other"></param>
		/// <returns></returns>
		public int CompareTo(X509Certificate other)
		{
			return Native.X509_cmp(this.ptr, other.ptr);
		}

		#endregion

		#region Fields
		private CryptoKey privateKey;
		#endregion
	}
}
