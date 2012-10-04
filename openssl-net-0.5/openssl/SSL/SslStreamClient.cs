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
using System.IO;
using OpenSSL.Core;
using OpenSSL.Crypto;
using OpenSSL.X509;

namespace OpenSSL.SSL
{
	class SslStreamClient : SslStreamBase
	{
		string targetHost;
		X509List clientCertificates;
		X509Chain caCertificates;
		// Internal callback for client certificate selection
		protected ClientCertCallbackHandler internalCertificateSelectionCallback;

		public SslStreamClient(Stream stream,
			bool ownStream,
			string targetHost,
			X509List clientCertificates,
			X509Chain caCertificates,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocationStatus,
			RemoteCertificateValidationHandler remoteCallback,
			LocalCertificateSelectionHandler localCallback)
			: base(stream, ownStream)
		{
			this.targetHost = targetHost;
			this.clientCertificates = clientCertificates;
			this.caCertificates = caCertificates;
			this.checkCertificateRevocationStatus = checkCertificateRevocationStatus;
			this.remoteCertificateSelectionCallback = remoteCallback;
			this.localCertificateSelectionCallback = localCallback;
			this.internalCertificateSelectionCallback = new ClientCertCallbackHandler(InternalClientCertificateSelectionCallback);
			InitializeClientContext(clientCertificates, enabledSslProtocols, sslStrength, checkCertificateRevocationStatus);
		}

		protected void InitializeClientContext(X509List certificates, SslProtocols enabledSslProtocols, SslStrength sslStrength, bool checkCertificateRevocation)
		{
			// Initialize the context with the specified ssl version
			// Initialize the context
			sslContext = new SslContext(SslMethod.SSLv23_client_method);

			// Remove support for protocols not specified in the enabledSslProtocols
			if ((enabledSslProtocols & SslProtocols.Ssl2) != SslProtocols.Ssl2)
			{
				sslContext.Options |= SslOptions.SSL_OP_NO_SSLv2;
			}
			if ((enabledSslProtocols & SslProtocols.Ssl3) != SslProtocols.Ssl3 &&
				((enabledSslProtocols & SslProtocols.Default) != SslProtocols.Default))
			{
				// no SSLv3 support
				sslContext.Options |= SslOptions.SSL_OP_NO_SSLv3;
			}
			if ((enabledSslProtocols & SslProtocols.Tls) != SslProtocols.Tls &&
				(enabledSslProtocols & SslProtocols.Default) != SslProtocols.Default)
			{
				sslContext.Options |= SslOptions.SSL_OP_NO_TLSv1;
			}

			// Set the Local certificate selection callback
			sslContext.SetClientCertCallback(this.internalCertificateSelectionCallback);
			// Set the enabled cipher list
			sslContext.SetCipherList(GetCipherString(false, enabledSslProtocols, sslStrength));
			// Set the callbacks for remote cert verification and local cert selection
			if (remoteCertificateSelectionCallback != null)
			{
				sslContext.SetVerify(VerifyMode.SSL_VERIFY_PEER | VerifyMode.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, remoteCertificateSelectionCallback);
			}
			// Set the CA list into the store
			if (caCertificates != null)
			{
				X509Store store = new X509Store(caCertificates);
				sslContext.SetCertificateStore(store);
			}
			// Set up the read/write bio's
			read_bio = BIO.MemoryBuffer(false);
			write_bio = BIO.MemoryBuffer(false);
			ssl = new Ssl(sslContext);
			ssl.SetBIO(read_bio, write_bio);
			read_bio.SetClose(BIO.CloseOption.Close);
			write_bio.SetClose(BIO.CloseOption.Close);
			// Set the Ssl object into Client mode
			ssl.SetConnectState();
		}

		internal protected override bool ProcessHandshake()
		{
			bool ret = false;

			// Check to see if we have an exception from the previous call
			//!!if (handshakeException != null)
			//!!{
			//!!    throw handshakeException;
			//!!}

			int nRet = 0;
			if (handShakeState == HandshakeState.InProcess)
			{
				nRet = ssl.Connect();
			}
			else if (handShakeState == HandshakeState.RenegotiateInProcess ||
					 handShakeState == HandshakeState.Renegotiate)
			{
				handShakeState = HandshakeState.RenegotiateInProcess;
				nRet = ssl.DoHandshake();
			}
			if (nRet <= 0)
			{
				SslError lastError = ssl.GetError(nRet);
				if (lastError == SslError.SSL_ERROR_WANT_READ)
				{
					// Do nothing -- the base stream will write the data from the bio
					// when this call returns
				}
				else if (lastError == SslError.SSL_ERROR_WANT_WRITE)
				{
					// unexpected error
					//!!TODO - debug log
				}
				else
				{
					// We should have alert data in the bio that needs to be written
					// We'll save the exception, allow the write to start, and then throw the exception
					// when we come back into the AsyncHandshakeCall
					if (write_bio.BytesPending > 0)
					{
						handshakeException = new OpenSslException();
					}
					else
					{
						throw new OpenSslException();
					}
				}
			}
			else
			{
				// Successful handshake
				ret = true;
			}
			return ret;
		}

		public int InternalClientCertificateSelectionCallback(Ssl ssl, out X509Certificate x509_cert, out CryptoKey key)
		{
			int nRet = 0;
			x509_cert = null;
			key = null;

			Core.Stack<X509Name> name_stack = ssl.CAList;
			string[] strIssuers = new string[name_stack.Count];
			int count = 0;

			foreach (X509Name name in name_stack)
			{
				strIssuers[count++] = name.OneLine;
			}

			if (localCertificateSelectionCallback != null)
			{
				X509Certificate cert = localCertificateSelectionCallback(this, targetHost, clientCertificates, ssl.GetPeerCertificate(), strIssuers);
				if (cert != null && cert.HasPrivateKey)
				{
					x509_cert = cert;
					key = cert.PrivateKey;
					// Addref the cert and private key
					x509_cert.AddRef();
					key.AddRef();
					// return success
					nRet = 1;
				}
			}

			return nRet;
		}
	}
}
