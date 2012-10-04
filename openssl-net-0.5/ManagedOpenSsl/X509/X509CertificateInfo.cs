// Copyright (c) 2009 Frank Laub
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
	internal class X509CertificateInfo : BaseReferenceType, IStackable
	{
		#region X509_INFO
		[StructLayout(LayoutKind.Sequential)]
		struct X509_INFO
		{
			public IntPtr x509;
			public IntPtr crl;
			public IntPtr x_pkey;
			#region EVP_CIPHER_INFO enc_cipher;
			public IntPtr cipher;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_IV_LENGTH)]
			public byte[] iv;
			#endregion
			public int enc_len;
			public IntPtr enc_data;
			public int references;
		}
		#endregion

		#region Initialization
		internal X509CertificateInfo(IStack stack, IntPtr ptr)
			: base(ptr, true)
		{
		}
		#endregion

		#region Properties

		public X509Certificate Certificate
		{
			get
			{
				X509Certificate ret = new X509Certificate(this.raw.x509, true);
				ret.AddRef();
				return ret;
			}
		}

		public CryptoKey Key
		{
			get
			{
				CryptoKey ret = new CryptoKey(this.raw.x_pkey, true);
				ret.AddRef();
				return ret;
			}
		}

		#endregion

		#region Overrides

		internal override void OnNewHandle(IntPtr ptr)
		{
			this.raw = (X509_INFO)Marshal.PtrToStructure(this.ptr, typeof(X509_INFO));
		}

		protected override void OnDispose()
		{
			Native.X509_INFO_free(this.ptr);
		}

		internal override CryptoLockTypes LockType
		{
			get { return CryptoLockTypes.CRYPTO_LOCK_X509_INFO; }
		}

		internal override Type RawReferenceType
		{
			get { return typeof(X509_INFO); }
		}

		#endregion

		#region Fields
		private X509_INFO raw;
		#endregion
	}

}
