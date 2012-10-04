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

namespace OpenSSL.SSL
{
	/// <summary>
	/// 
	/// </summary>
	public enum CipherAlgorithmType
	{
		/// <summary>
		/// 
		/// </summary>
		None,
		/// <summary>
		/// 
		/// </summary>
		Rc2,
		/// <summary>
		/// 
		/// </summary>
		Rc4,
		/// <summary>
		/// 
		/// </summary>
		Des,
		/// <summary>
		/// 
		/// </summary>
		Idea,
		/// <summary>
		/// 
		/// </summary>
		Fortezza,
		/// <summary>
		/// 
		/// </summary>
		Camellia128,
		/// <summary>
		/// 
		/// </summary>
		Camellia256,
		/// <summary>
		/// 
		/// </summary>
		Seed,
		/// <summary>
		/// 
		/// </summary>
		TripleDes,
		/// <summary>
		/// 
		/// </summary>
		Aes,
		/// <summary>
		/// 
		/// </summary>
		Aes128,
		/// <summary>
		/// 
		/// </summary>
		Aes192,
		/// <summary>
		/// 
		/// </summary>
		Aes256
	}

	/// <summary>
	/// 
	/// </summary>
	public enum HashAlgorithmType
	{
		/// <summary>
		/// 
		/// </summary>
		None,
		/// <summary>
		/// 
		/// </summary>
		Md5,
		/// <summary>
		/// 
		/// </summary>
		Sha1
	}

	/// <summary>
	/// 
	/// </summary>
	public enum ExchangeAlgorithmType
	{
		/// <summary>
		/// 
		/// </summary>
		None,
		/// <summary>
		/// 
		/// </summary>
		RsaSign,
		/// <summary>
		/// 
		/// </summary>
		RsaKeyX,
		/// <summary>
		/// 
		/// </summary>
		DiffieHellman,
		/// <summary>
		/// 
		/// </summary>
		Kerberos,
		/// <summary>
		/// 
		/// </summary>
		Fortezza,
		/// <summary>
		/// 
		/// </summary>
		ECDiffieHellman
	}

	/// <summary>
	/// 
	/// </summary>
	public enum SslProtocols
	{
		/// <summary>
		/// 
		/// </summary>
		None = 0,
		/// <summary>
		/// 
		/// </summary>
		Ssl2 = 1,
		/// <summary>
		/// 
		/// </summary>
		Ssl3 = 2,
		/// <summary>
		/// 
		/// </summary>
		Tls = 4,
		/// <summary>
		/// 
		/// </summary>
		Default = 16
	}

	/// <summary>
	/// 
	/// </summary>
	public enum SslStrength
	{
		/// <summary>
		/// 
		/// </summary>
		High = 4,   //256
		/// <summary>
		/// 
		/// </summary>
		Medium = 2, //128
		/// <summary>
		/// 
		/// </summary>
		Low = 1,    //40
		/// <summary>
		/// 
		/// </summary>
		All = High | Medium | Low
	}

	enum SslFileType
	{
		/// <summary>
		/// SSL_FILETYPE_PEM
		/// </summary>
		PEM = 1,
		/// <summary>
		/// SSL_FILETYPE_ASN1
		/// </summary>
		ASN1 = 2
	}

	enum AuthenticationMethod
	{
		None,
		Rsa,
		Dss,
		DiffieHellman,
		Kerberos,
		ECDsa
	}

	enum HandshakeState
	{
		None,
		Renegotiate,
		InProcess,
		RenegotiateInProcess,
		Complete
	}


	/// <summary>
	/// Options enumeration for Options property
	/// </summary>
	enum SslOptions
	{
		SSL_OP_MICROSOFT_SESS_ID_BUG = 0x00000001,
		SSL_OP_NETSCAPE_CHALLENGE_BUG = 0x00000002,
		SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000008,
		SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x00000010,
		SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 0x00000020,
		SSL_OP_MSIE_SSLV2_RSA_PADDING = 0x00000040, /* no effect since 0.9.7h and 0.9.8b */
		SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 0x00000080,
		SSL_OP_TLS_D5_BUG = 0x00000100,
		SSL_OP_TLS_BLOCK_PADDING_BUG = 0x00000200,

		/* Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added
		 * in OpenSSL 0.9.6d.  Usually (depending on the application protocol)
		 * the workaround is not needed.  Unfortunately some broken SSL/TLS
		 * implementations cannot handle it at all, which is why we include
		 * it in SSL_OP_ALL. */
		SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800, /* added in 0.9.6e */

		/* SSL_OP_ALL: various bug workarounds that should be rather harmless.
		 *             This used to be 0x000FFFFFL before 0.9.7. */
		SSL_OP_ALL = (0x00000FFF ^ SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG),

		/* As server, disallow session resumption on renegotiation */
		SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000,
		/* If set, always create a new key when using tmp_dh parameters */
		SSL_OP_SINGLE_DH_USE = 0x00100000,
		/* Set to always use the tmp_rsa key when doing RSA operations,
		 * even when this violates protocol specs */
		SSL_OP_EPHEMERAL_RSA = 0x00200000,
		/* Set on servers to choose the cipher according to the server's
		 * preferences */
		SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000,
		/* If set, a server will allow a client to issue a SSLv3.0 version number
		 * as latest version supported in the premaster secret, even when TLSv1.0
		 * (version 3.1) was announced in the client hello. Normally this is
		 * forbidden to prevent version rollback attacks. */
		SSL_OP_TLS_ROLLBACK_BUG = 0x00800000,

		SSL_OP_NO_SSLv2 = 0x01000000,
		SSL_OP_NO_SSLv3 = 0x02000000,
		SSL_OP_NO_TLSv1 = 0x04000000,

		/* The next flag deliberately changes the ciphertest, this is a check
		 * for the PKCS#1 attack */
		SSL_OP_PKCS1_CHECK_1 = 0x08000000,
		SSL_OP_PKCS1_CHECK_2 = 0x10000000,
		SSL_OP_NETSCAPE_CA_DN_BUG = 0x20000000,
		SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x40000000,
	}

	enum SslMode
	{
		/* Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
		 * when just a single record has been written): */
		SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001,
		/* Make it possible to retry SSL_write() with changed buffer location
		 * (buffer contents must stay the same!); this is not the default to avoid
		 * the misconception that non-blocking SSL_write() behaves like
		 * non-blocking write(): */
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002,
		/* Never bother the application with retries if the transport
		 * is blocking: */
		SSL_MODE_AUTO_RETRY = 0x00000004,
		/* Don't attempt to automatically build certificate chain */
		SSL_MODE_NO_AUTO_CHAIN = 0x00000008
	}

	enum VerifyMode
	{
		SSL_VERIFY_NONE = 0x00,
		SSL_VERIFY_PEER = 0x01,
		SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02,
		SSL_VERIFY_CLIENT_ONCE = 0x04,
	}

}
