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
using OpenSSL.X509;

namespace OpenSSL.SSL
{
	enum SslError
	{
		SSL_ERROR_NONE = 0,
		SSL_ERROR_SSL = 1,
		SSL_ERROR_WANT_READ = 2,
		SSL_ERROR_WANT_WRITE = 3,
		SSL_ERROR_WANT_X509_LOOKUP = 4,
		SSL_ERROR_SYSCALL = 5, /* look at error stack/return value/errno */
		SSL_ERROR_ZERO_RETURN = 6,
		SSL_ERROR_WANT_CONNECT = 7,
		SSL_ERROR_WANT_ACCEPT = 8
	}

	class Ssl : Base, IDisposable
	{
		internal const int SSL_ST_CONNECT = 0x1000;
		internal const int SSL_ST_ACCEPT = 0x2000;

		#region ssl_st

		[StructLayout(LayoutKind.Sequential)]
		struct ssl_st
		{
			/* protocol version
			 * (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION, DTLS1_VERSION)
			 */
			public int version;
			public int type; /* SSL_ST_CONNECT or SSL_ST_ACCEPT */

			public IntPtr method;  //SSL_METHOD *method; /* SSLv3 */

			/* There are 2 BIO's even though they are normally both the
			 * same.  This is so data can be read and written to different
			 * handlers */

#if ! OPENSSL_NO_BIO
			public IntPtr rbio;    //BIO *rbio; /* used by SSL_read */
			public IntPtr wbio;    //BIO *wbio; /* used by SSL_write */
			public IntPtr bbio;    //BIO *bbio; /* used during session-id reuse to concatenate messages */
#else
	        char *rbio; /* used by SSL_read */
	        char *wbio; /* used by SSL_write */
	        char *bbio;
#endif
			/* This holds a variable that indicates what we were doing
	         * when a 0 or -1 is returned.  This is needed for
	         * non-blocking IO so we know what request needs re-doing when
	         * in SSL_accept or SSL_connect */
			public int rwstate;

			/* true when we are actually in SSL_accept() or SSL_connect() */
			public int in_handshake;
			public IntPtr handshake_func;  //int (*handshake_func)(SSL *);

			/* Imagine that here's a boolean member "init" that is
			 * switched as soon as SSL_set_{accept/connect}_state
			 * is called for the first time, so that "state" and
			 * "handshake_func" are properly initialized.  But as
			 * handshake_func is == 0 until then, we use this
			 * test instead of an "init" member.
			 */

			public int server;	/* are we the server side? - mostly used by SSL_clear*/

			public int new_session;/* 1 if we are to use a new session.
	                         * 2 if we are a server and are inside a handshake
	                         *   (i.e. not just sending a HelloRequest)
	                         * NB: For servers, the 'new' session may actually be a previously
	                         * cached session or even the previous session unless
	                         * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set */
			public int quiet_shutdown;/* don't send shutdown packets */
			public int shutdown;	/* we have shut things down, 0x01 sent, 0x02 for received */
			public int state;	/* where we are */
			public int rstate;	/* where we are when reading */

			public IntPtr init_buf;    //BUF_MEM *init_buf;	/* buffer used during init */
			public IntPtr init_msg;    //void *init_msg;   	/* pointer to handshake message body, set by ssl3_get_message() */
			public int init_num;		/* amount read/written */
			public int init_off;		/* amount read/written */

			/* used internally to point at a raw packet */
			public IntPtr packet;  //unsigned char *packet;
			public uint packet_length; //unsigned int packet_length;

			public IntPtr s2;  //struct ssl2_state_st *s2; /* SSLv2 variables */
			public IntPtr s3;  //struct ssl3_state_st *s3; /* SSLv3 variables */
			public IntPtr d1;  //struct dtls1_state_st *d1; /* DTLSv1 variables */

			public int read_ahead;		/* Read as many input bytes as possible (for non-blocking reads) */

			/* callback that allows applications to peek at protocol messages */
			public IntPtr msg_callback;    //void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
			public IntPtr msg_callback_arg;    //void *msg_callback_arg;

			public int hit;		/* reusing a previous session */

			public IntPtr param;   //X509_VERIFY_PARAM *param;

#if FALSE // #if 0
	        int purpose;		/* Purpose setting */
	        int trust;		/* Trust setting */
#endif

			/* crypto */
			public IntPtr cipher_list;     //STACK_OF(SSL_CIPHER) *cipher_list;
			public IntPtr cipher_list_by_id;   //STACK_OF(SSL_CIPHER) *cipher_list_by_id;

			/* These are the ones being used, the ones in SSL_SESSION are
			 * the ones to be 'copied' into these ones */

			public IntPtr enc_read_ctx;    //EVP_CIPHER_CTX *enc_read_ctx;		/* cryptographic state */
			public IntPtr read_hash;       //const EVP_MD *read_hash;		/* used for mac generation */
#if ! OPENSSL_NO_COMP
			public IntPtr expand;      //COMP_CTX *expand;			/* uncompress */
#else
	        char *expand;
#endif

			public IntPtr enc_write_ctx;   //EVP_CIPHER_CTX *enc_write_ctx;		/* cryptographic state */
			public IntPtr write_hash;      //const EVP_MD *write_hash;		/* used for mac generation */
#if ! OPENSSL_NO_COMP
			public IntPtr compress;    //COMP_CTX *compress;			/* compression */
#else
	        char *compress;	
#endif

			/* session info */

			/* client cert? */
			/* This is used to hold the server certificate used */
			public IntPtr cert;    //struct cert_st /* CERT */ *cert;

			/* the session_id_context is used to ensure sessions are only reused
			 * in the appropriate context */
			public uint sid_ctx_length;    //unsigned int sid_ctx_length;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.SSL_MAX_SID_CTX_LENGTH)]
			public byte[] sid_ctx;   //unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];

			/* This can also be in the session once a session is established */
			public IntPtr session;  //SSL_SESSION *session;

			/* Default generate session ID callback. */
			public IntPtr generate_session_id; //GEN_SESSION_CB generate_session_id;

			/* Used in SSL2 and SSL3 */
			public int verify_mode;	/* 0 don't care about verify failure.
				         * 1 fail if verify fails */
			public IntPtr verify_callback;  //int (*verify_callback)(int ok,X509_STORE_CTX *ctx); /* fail if callback returns 0 */

			public IntPtr info_callback;    //void (*info_callback)(const SSL *ssl,int type,int val); /* optional informational callback */

			public int error;		/* error bytes to be written */
			public int error_code;		/* actual code */

#if !OPENSSL_NO_KRB5
			public IntPtr kssl_ctx; //KSSL_CTX *kssl_ctx;     /* Kerberos 5 context */
#endif	// OPENSSL_NO_KRB5

			public IntPtr ctx;  //SSL_CTX *ctx;
			/* set this flag to 1 and a sleep(1) is put into all SSL_read()
			 * and SSL_write() calls, good for nbio debuging :-) */
			public int debug;

			/* extra application data */
			public int verify_result;   //long verify_result;
			//	        CRYPTO_EX_DATA ex_data;
			#region CRYPTO_EX_DATA ex_data;
			public IntPtr ex_data_sk;
			public int ex_data_dummy;
			#endregion

			/* for server side, keep the list of CA_dn we can use */
			public IntPtr client_CA;    //STACK_OF(X509_NAME) *client_CA;

			public int references;
			public uint options; //unsigned long options; /* protocol behaviour */
			public uint mode;    //unsigned long mode; /* API behaviour */
			public int max_cert_list;   //long max_cert_list;
			public int first_packet;
			public int client_version;	/* what was passed, used for
				         * SSLv3/TLS rollback check */
#if ! OPENSSL_NO_TLSEXT
			/* TLS extension debug callback */
			public IntPtr tlsext_debug_cb;  //void (*tlsext_debug_cb)(SSL *s, int client_server, int type, unsigned char *data, int len, void *arg);
			public IntPtr tlsext_debug_arg; //void *tlsext_debug_arg;
			public IntPtr tlsext_hostname;  //char *tlsext_hostname;
			public int servername_done;   /* no further mod of servername 
	                                  0 : call the servername extension callback.
	                                  1 : prepare 2, allow last ack just after in server callback.
	                                  2 : don't call servername callback, no ack in server hello
	                               */
			/* certificate status request info */
			/* Status type or -1 if no status type */
			public int tlsext_status_type;
			/* Expect OCSP CertificateStatus message */
			public int tlsext_status_expected;
			/* OCSP status request only */
			public IntPtr tlsext_ocsp_ids;  //STACK_OF(OCSP_RESPID) *tlsext_ocsp_ids;
			public IntPtr tlsext_ocsp_exts; //X509_EXTENSIONS *tlsext_ocsp_exts;
			/* OCSP response received or to be sent */
			public IntPtr tlsext_ocsp_resp; //unsigned char *tlsext_ocsp_resp;
			public int tlsext_ocsp_resplen;

			/* RFC4507 session ticket expected to be received or sent */
			public int tlsext_ticket_expected;
			public IntPtr initial_ctx;  //SSL_CTX * initial_ctx; /* initial ctx, used to store sessions */
#endif //! OPENSSL_NO_TLSEXT
		}

		#endregion

		#region Initialization

		/// <summary>
		/// Calls SSL_new()
		/// </summary>
		/// <param name="ctx"></param>
		public Ssl(SslContext ctx) :
			base(Native.ExpectNonNull(Native.SSL_new(ctx.Handle)), true)
		{ }

		internal Ssl(IntPtr ptr, bool takeOwnership)
			: base(ptr, takeOwnership)
		{ }

		#endregion

		#region Properties
		public int State
		{
			get
			{
				int offset = (int)Marshal.OffsetOf(typeof(ssl_st), "state");
				IntPtr offset_ptr = new IntPtr((int)this.ptr + offset);
				return Marshal.ReadInt32(offset_ptr);
			}
			set
			{
				int offset = (int)Marshal.OffsetOf(typeof(ssl_st), "state");
				IntPtr offset_ptr = new IntPtr((int)this.ptr + offset);
				Marshal.WriteInt32(offset_ptr, value);
			}
		}

		public SslCipher CurrentCipher
		{
			get { return new SslCipher(Native.SSL_get_current_cipher(this.Handle), false); }
		}

		public Core.Stack<X509Name> CAList
		{
			get
			{
				IntPtr ptr = Native.SSL_get_client_CA_list(this.ptr);
				Core.Stack<X509Name> name_stack = new Core.Stack<X509Name>(ptr, false);
				return name_stack;
			}
			set
			{
				Native.SSL_set_client_CA_list(this.ptr, value.Handle);
			}
		}

		public X509Certificate LocalCertificate
		{
			get
			{
				IntPtr cert = Native.ExpectNonNull(Native.SSL_get_certificate(this.ptr));
				return new X509Certificate(cert, false);
			}
			set
			{
				Native.ExpectSuccess(Native.SSL_use_certificate(this.ptr, value.Handle));
			}
		}

		public X509Certificate RemoteCertificate
		{
			get { return GetPeerCertificate(); }
		}

		#endregion

		#region Methods

		public int Accept()
		{
			return Native.SSL_accept(this.ptr);
		}

		public int Connect()
		{
			return Native.SSL_connect(this.ptr);
		}

		public SslError GetError(int ret_code)
		{
			return (SslError)Native.SSL_get_error(this.ptr, ret_code);
		}

		public X509Certificate GetPeerCertificate()
		{
			IntPtr cert_ptr = Native.ExpectNonNull(Native.SSL_get_peer_certificate(this.ptr));
			X509Certificate cert = new X509Certificate(cert_ptr, true);
			return cert;
		}

		public VerifyResult GetVerifyResult()
		{
			return (VerifyResult)Native.SSL_get_verify_result(this.ptr);
		}

		public void SetVerifyResult(VerifyResult result)
		{
			Native.SSL_set_verify_result(this.ptr, (int)result);
		}

		public int Shutdown()
		{
			return Native.SSL_shutdown(this.ptr);
		}

		public int Write(byte[] buf, int len)
		{
			return Native.SSL_write(this.ptr, buf, len);
		}

		public int Read(byte[] buf, int len)
		{
			return Native.SSL_read(this.ptr, buf, len);
		}

		public int SetSessionIdContext(byte[] sid_ctx, uint sid_ctx_len)
		{
			return Native.ExpectSuccess(Native.SSL_set_session_id_context(this.ptr, sid_ctx, sid_ctx_len));
		}

		public int Renegotiate()
		{
			return Native.ExpectSuccess(Native.SSL_renegotiate(this.ptr));
		}

		public int DoHandshake()
		{
			return Native.SSL_do_handshake(this.ptr);
		}

		public void SetAcceptState()
		{
			Native.SSL_set_accept_state(this.ptr);
		}

		public void SetConnectState()
		{
			Native.SSL_set_connect_state(this.ptr);
		}

		public void SetBIO(BIO read, BIO write)
		{
			Native.SSL_set_bio(this.ptr, read.Handle, write.Handle);
		}

		public int UseCertificateFile(string filename, SslFileType type)
		{
			return Native.ExpectSuccess(Native.SSL_use_certificate_file(this.ptr, filename, (int)type));
		}

		public int UsePrivateKeyFile(string filename, SslFileType type)
		{
			return Native.ExpectSuccess(Native.SSL_use_PrivateKey_file(this.ptr, filename, (int)type));
		}

		public int Clear()
		{
			return Native.ExpectSuccess(Native.SSL_clear(this.ptr));
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls SSL_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.SSL_free(this.Handle);
		}

		#endregion

	}
}
