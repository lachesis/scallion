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
using OpenSSL.X509;

namespace OpenSSL.SSL
{
    class SslStreamServer : SslStreamBase
    {
        public SslStreamServer(
            Stream stream, 
            bool ownStream,
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            X509Chain caCerts,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            bool checkCertificateRevocation,
            RemoteCertificateValidationHandler remote_callback)
            : base(stream, ownStream)
        {
            this.checkCertificateRevocationStatus = checkCertificateRevocation;
            this.remoteCertificateSelectionCallback = remote_callback;

            // Initialize the SslContext object
            InitializeServerContext(serverCertificate, clientCertificateRequired, caCerts, enabledSslProtocols, sslStrength, checkCertificateRevocation);
            
            // Initalize the Ssl object
            ssl = new Ssl(sslContext);
            // Initialze the read/write bio
            read_bio = BIO.MemoryBuffer(false);
            write_bio = BIO.MemoryBuffer(false);
            // Set the read/write bio's into the the Ssl object
            ssl.SetBIO(read_bio, write_bio);
            read_bio.SetClose(BIO.CloseOption.Close);
            write_bio.SetClose(BIO.CloseOption.Close);
            // Set the Ssl object into server mode
            ssl.SetAcceptState();
        }

        internal protected override bool ProcessHandshake()
        {
            bool bRet = false;
            int nRet = 0;
            
            if (handShakeState == HandshakeState.InProcess)
            {
                nRet = ssl.Accept();
            }
            else if (handShakeState == HandshakeState.RenegotiateInProcess)
            {
                nRet = ssl.DoHandshake();
            }
            else if (handShakeState == HandshakeState.Renegotiate)
            {
                nRet = ssl.DoHandshake();
                ssl.State = Ssl.SSL_ST_ACCEPT;
                handShakeState = HandshakeState.RenegotiateInProcess;
            }
            SslError lastError = ssl.GetError(nRet);
            if (lastError == SslError.SSL_ERROR_WANT_READ || lastError == SslError.SSL_ERROR_WANT_WRITE || lastError == SslError.SSL_ERROR_NONE)
            {
                if (nRet == 1) // success
                {
                    bRet = true;
                }
            }
            else
            {
                // Check to see if we have alert data in the write_bio that needs to be sent
                if (write_bio.BytesPending > 0)
                {
                    // We encountered an error, but need to send the alert
                    // set the handshakeException so that it will be processed
                    // and thrown after the alert is sent
                    handshakeException = new OpenSslException();
                }
                else
                {
                    // No alert to send, throw the exception
                    throw new OpenSslException();
                }
            }
            return bRet;
        }

        private void InitializeServerContext(
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            X509Chain caCerts,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            bool checkCertificateRevocation)
        {
            if (serverCertificate == null)
            {
                throw new ArgumentNullException("serverCertificate", "Server certificate cannot be null");
            }
            if (!serverCertificate.HasPrivateKey)
            {
                throw new ArgumentException("Server certificate must have a private key", "serverCertificate");
            }

            // Initialize the context
            sslContext = new SslContext(SslMethod.SSLv23_server_method);
            
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
            /*
            // Initialize the context with the specified ssl version
            switch (enabledSslProtocols)
            {
                case SslProtocols.None:
                    throw new ArgumentException("SslProtocol.None is not supported", "enabledSslProtocols");
                    break;
                case SslProtocols.Ssl2:
                    sslContext = new SslContext(SslMethod.SSLv2_server_method);
                    break;
                case SslProtocols.Ssl3:
                case SslProtocols.Default:
                    sslContext = new SslContext(SslMethod.SSLv3_server_method);
                    break;
                case SslProtocols.Tls:
                    sslContext = new SslContext(SslMethod.TLSv1_server_method);
                    break;
            }
            */
            // Set the context mode
            sslContext.Mode = SslMode.SSL_MODE_AUTO_RETRY;
            // Set the workaround options
            sslContext.Options = SslOptions.SSL_OP_ALL;
            // Set the client certificate verification callback if we are requiring client certs
            if (clientCertificateRequired)
            {
                sslContext.SetVerify(VerifyMode.SSL_VERIFY_PEER | VerifyMode.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, remoteCertificateSelectionCallback);
            }
            else
            {
                sslContext.SetVerify(VerifyMode.SSL_VERIFY_NONE, null);
            }

            // Set the client certificate max verification depth
            sslContext.SetVerifyDepth(10);
            // Set the certificate store and ca list
            if (caCerts != null)
            {
                // Don't take ownership of the X509Store IntPtr.  When we
                // SetCertificateStore, the context takes ownership of the store pointer.
                X509Store cert_store = new X509Store(caCerts, false);
                sslContext.SetCertificateStore(cert_store);
                Core.Stack<X509Name> name_stack = new Core.Stack<X509Name>();
                foreach (X509Certificate cert in caCerts)
                {
                    X509Name subject = cert.Subject;
                    name_stack.Add(subject);
                }
                // Assign the stack to the context
                sslContext.CAList = name_stack;
            }
            // Set the cipher string
            sslContext.SetCipherList(GetCipherString(false, enabledSslProtocols, sslStrength));
            // Set the certificate
            sslContext.UseCertificate(serverCertificate);
            // Set the private key
            sslContext.UsePrivateKey(serverCertificate.PrivateKey);
            // Set the session id context
            sslContext.SetSessionIdContext(Encoding.ASCII.GetBytes(AppDomain.CurrentDomain.FriendlyName));
        }
    }
}
