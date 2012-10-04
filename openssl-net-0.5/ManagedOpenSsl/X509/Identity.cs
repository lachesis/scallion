// Copyright (c) 2006-2007 Frank Laub
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
using OpenSSL.Crypto;

namespace OpenSSL.X509
{
	/// <summary>
	/// Simple encapsulation of a local identity.
	/// This includes the private key and the X509Certificate.
	/// </summary>
	public class Identity
	{
		private CryptoKey key;
		private X509Certificate cert;

		/// <summary>
		/// Construct an Identity with a private key
		/// </summary>
		/// <param name="key"></param>
		public Identity(CryptoKey key)
		{
			this.key = key;
		}

		#region Properties

		/// <summary>
		/// Returns the embedded public key of the X509Certificate
		/// </summary>
		public CryptoKey PublicKey
		{
			get { return this.cert.PublicKey; }
		}

		/// <summary>
		/// Returns the private key
		/// </summary>
		public CryptoKey PrivateKey
		{
			get { return this.key; }
		}

		/// <summary>
		/// Returns the X509Certificate
		/// </summary>
		public X509Certificate Certificate
		{
			get { return this.cert; }
		}
		#endregion

		#region Methods
		/// <summary>
		/// Create a X509Request for this identity, using the specified name.
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public X509Request CreateRequest(string name)
		{
            return CreateRequest(name, MessageDigest.DSS1);
		}

        /// <summary>
        /// Create a X509Request for this identity, using the specified name and digest.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="digest"></param>
        /// <returns></returns>
        public X509Request CreateRequest(string name, MessageDigest digest)
        {
            X509Name subject = new X509Name(name);
            X509Request request = new X509Request(2, subject, this.key);

            request.Sign(key, digest);

            return request;
        }

		/// <summary>
		/// Verify that the specified chain can be trusted.
		/// </summary>
		/// <param name="chain"></param>
		/// <param name="error"></param>
		/// <returns></returns>
		public bool VerifyResponse(X509Chain chain, out string error)
		{
            this.cert = chain[0];
			X509Store store = new X509Store(chain);
			return store.Verify(cert, out error);
		}
		#endregion
	}
}
