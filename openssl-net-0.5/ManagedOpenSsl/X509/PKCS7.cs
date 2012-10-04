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

namespace OpenSSL.X509
{
	/// <summary>
	/// Wraps PKCS7
	/// </summary>
	public class PKCS7 : Base
	{
		#region PKCS7 structures
		const int NID_pkcs7_signed = 22; // from obj_mac.h
		const int NID_pkcs7_signedAndEnveloped = 24; // from obj_mac.h

		// State definitions
		const int PKCS7_S_HEADER = 0;
		const int PKCS7_S_BODY = 1;
		const int PKCS7_S_TAIL = 2;

		[StructLayout(LayoutKind.Sequential)]
		private struct _PKCS7
		{
			/* The following is non NULL if it contains ASN1 encoding of
			 * this structure */
			public IntPtr asn1;    //unsigned char *asn1;
			public int length;     //long length;
			public int state;      /* used during processing */
			public int detached;
			public IntPtr type;    //ASN1_OBJECT *type;
			/* content as defined by the type */
			/* all encryption/message digests are applied to the 'contents',
			 * leaving out the 'type' field. */
			public IntPtr ptr;     //char *ptr;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct PKCS7_SIGNED
		{
			public IntPtr version;      //ASN1_INTEGER			*version;	/* version 1 */
			public IntPtr md_algs;      //STACK_OF(X509_ALGOR)		*md_algs;	/* md used */
			public IntPtr cert;         //STACK_OF(X509)			*cert;		/* [ 0 ] */
			public IntPtr crl;          //STACK_OF(X509_CRL)		*crl;		/* [ 1 ] */
			public IntPtr signer_info;  //STACK_OF(PKCS7_SIGNER_INFO)	*signer_info;
			public IntPtr contents;     //struct pkcs7_st			*contents;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct PKCS7_SIGN_ENVELOPE
		{
			public IntPtr version;          //ASN1_INTEGER			*version;	/* version 1 */
			public IntPtr md_algs;          //STACK_OF(X509_ALGOR)		*md_algs;	/* md used */
			public IntPtr cert;             //STACK_OF(X509)			*cert;		/* [ 0 ] */
			public IntPtr crl;              //STACK_OF(X509_CRL)		*crl;		/* [ 1 ] */
			public IntPtr signer_info;      //STACK_OF(PKCS7_SIGNER_INFO)	*signer_info;
			public IntPtr enc_data;         //PKCS7_ENC_CONTENT		*enc_data;
			public IntPtr recipientinfo;    //STACK_OF(PKCS7_RECIP_INFO)	*recipientinfo;
		}

		#endregion

		#region Initialization

		private PKCS7(IntPtr ptr)
			: base(ptr, true)
		{ }

		/// <summary>
		/// Calls d2i_PKCS7_bio()
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static PKCS7 FromDER(BIO bio)
		{
			return new PKCS7(Native.ExpectNonNull(Native.d2i_PKCS7_bio(bio.Handle, IntPtr.Zero)));
		}

		/// <summary>
		/// Calls PEM_read_bio_PKCS7()
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static PKCS7 FromPEM(BIO bio)
		{
			return new PKCS7(Native.ExpectNonNull(Native.PEM_read_bio_PKCS7(bio.Handle, IntPtr.Zero, null, IntPtr.Zero)));
		}

		#endregion

		#region Properties

		/// <summary>
		/// Extracts the X509Chain of certifcates from the internal PKCS7 structure
		/// </summary>
		public X509Chain Certificates
		{
			get
			{
				if (this.stack == null)
				{
					int type = Native.OBJ_obj2nid(this.raw.type);
					switch (type)
					{
						case NID_pkcs7_signed:
							this.stack = GetStackFromSigned();
							break;
						case NID_pkcs7_signedAndEnveloped:
							this.stack = GetStackFromSignedAndEnveloped();
							break;
						default:
							throw new NotSupportedException();
					}
				}

				// Can we remove this and just use a Chain to begin with?
				X509Chain chain = null;
				if (this.stack != null)
				{
					chain = new X509Chain();
					// We have a stack of certificates, build the chain object and return
					foreach (X509Certificate cert in this.stack)
					{
						chain.Add(cert);
					}
				}
				return chain;
			}
		}

		#endregion

		#region Helpers

		private Core.Stack<X509Certificate> GetStackFromSigned()
		{
			PKCS7_SIGNED signed = (PKCS7_SIGNED)Marshal.PtrToStructure(raw.ptr, typeof(PKCS7_SIGNED));
			return new Core.Stack<X509Certificate>(signed.cert, false);
		}

		private Core.Stack<X509Certificate> GetStackFromSignedAndEnveloped()
		{
			PKCS7_SIGN_ENVELOPE envelope = (PKCS7_SIGN_ENVELOPE)Marshal.PtrToStructure(raw.ptr, typeof(PKCS7_SIGN_ENVELOPE));
			return new Core.Stack<X509Certificate>(envelope.cert, false);
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls PKCS7_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.PKCS7_free(this.ptr);
		}

		internal override void OnNewHandle(IntPtr ptr)
		{
			this.raw = (_PKCS7)Marshal.PtrToStructure(ptr, typeof(_PKCS7));
		}

		#endregion

		#region Fields
		private _PKCS7 raw;
		private Core.Stack<X509Certificate> stack;
		#endregion
	}
}
