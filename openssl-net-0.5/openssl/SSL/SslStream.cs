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
using System.Net.Security;
using System.IO;
using OpenSSL.X509;

namespace OpenSSL.SSL
{
	/// <summary>
	/// 
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="cert"></param>
	/// <param name="chain"></param>
	/// <param name="depth"></param>
	/// <param name="result"></param>
	/// <returns></returns>
	public delegate bool RemoteCertificateValidationHandler(Object sender, X509Certificate cert, X509Chain chain, int depth, VerifyResult result);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="targetHost"></param>
	/// <param name="localCerts"></param>
	/// <param name="remoteCert"></param>
	/// <param name="acceptableIssuers"></param>
	/// <returns></returns>
	public delegate X509Certificate LocalCertificateSelectionHandler(Object sender, string targetHost, X509List localCerts, X509Certificate remoteCert, string[] acceptableIssuers);

	/// <summary>
	/// Implments an AuthenticatedStream and is the main interface to the SSL library.
	/// </summary>
	public class SslStream : AuthenticatedStream
	{
		#region Initialization

		/// <summary>
		/// Create an SslStream based on an existing stream.
		/// </summary>
		/// <param name="stream"></param>
		public SslStream(Stream stream)
			: this(stream, false)
		{
		}

		/// <summary>
		/// Create an SslStream based on an existing stream.
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="leaveInnerStreamOpen"></param>
		public SslStream(Stream stream, bool leaveInnerStreamOpen)
			: base(stream, leaveInnerStreamOpen)
		{
			remoteCertificateValidationCallback = null;
			localCertificateSelectionCallback = null;
		}

		/// <summary>
		/// Create an SslStream based on an existing stream.
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="leaveInnerStreamOpen"></param>
		/// <param name="remote_callback"></param>
		public SslStream(Stream stream, bool leaveInnerStreamOpen, RemoteCertificateValidationHandler remote_callback)
			: this(stream, leaveInnerStreamOpen, remote_callback, null)
		{
		}

		/// <summary>
		/// Create an SslStream based on an existing stream.
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="leaveInnerStreamOpen"></param>
		/// <param name="remote_callback"></param>
		/// <param name="local_callback"></param>
		public SslStream(Stream stream, bool leaveInnerStreamOpen, RemoteCertificateValidationHandler remote_callback, LocalCertificateSelectionHandler local_callback)
			: base(stream, leaveInnerStreamOpen)
		{
			remoteCertificateValidationCallback = remote_callback;
			localCertificateSelectionCallback = local_callback;
		}
		#endregion

		#region AuthenticatedStream Members
		/// <summary>
		/// Returns whether authentication was successful.
		/// </summary>
		public override bool IsAuthenticated
		{
			get { return sslStream != null; }
		}

		/// <summary>
		/// Indicates whether data sent using this SslStream is encrypted.
		/// </summary>
		public override bool IsEncrypted
		{
			get { return IsAuthenticated; }
		}

		/// <summary>
		/// Indicates whether both server and client have been authenticated.
		/// </summary>
		public override bool IsMutuallyAuthenticated
		{
			get
			{
				if (IsAuthenticated && (IsServer ? sslStream.RemoteCertificate != null : sslStream.LocalCertificate != null))
				{
					return true;
				}
				return false;
			}
		}

		/// <summary>
		/// Indicates whether the local side of the connection was authenticated as the server.
		/// </summary>
		public override bool IsServer
		{
			get { return sslStream is SslStreamServer; }
		}

		/// <summary>
		/// Indicates whether the data sent using this stream is signed.
		/// </summary>
		public override bool IsSigned
		{
			get { return IsAuthenticated; }
		}

		#endregion

		#region Stream Members
		/// <summary>
		/// Gets a value indicating whether the current stream supports reading.
		/// </summary>
		public override bool CanRead
		{
			get { return InnerStream.CanRead; }
		}

		/// <summary>
		/// Gets a value indicating whether the current stream supports seeking.
		/// </summary>
		public override bool CanSeek
		{
			get { return InnerStream.CanSeek; }
		}

		/// <summary>
		/// Gets a value indicating whether the current stream supports writing.
		/// </summary>
		public override bool CanWrite
		{
			get { return InnerStream.CanWrite; }
		}

		/// <summary>
		/// Clears all buffers for this stream and causes any buffered data to be written to the underlying device.
		/// </summary>
		public override void Flush()
		{
			InnerStream.Flush();
		}

		/// <summary>
		/// Gets the length in bytes of the stream.
		/// </summary>
		public override long Length
		{
			get { return InnerStream.Length; }
		}

		/// <summary>
		/// Gets or sets the position within the current stream.
		/// </summary>
		public override long Position
		{
			get { return InnerStream.Position; }
			set { throw new NotSupportedException(); }
		}

		/// <summary>
		/// Gets or sets a value, in miliseconds, that determines how long the stream will attempt to read before timing out.
		/// </summary>
		public override int ReadTimeout
		{
			get { return InnerStream.ReadTimeout; }
			set { InnerStream.ReadTimeout = value; }
		}

		/// <summary>
		/// Gets or sets a value, in miliseconds, that determines how long the stream will attempt to write before timing out.
		/// </summary>
		public override int WriteTimeout
		{
			get { return InnerStream.WriteTimeout; }
			set { InnerStream.WriteTimeout = value; }
		}

		/// <summary>
		/// Reads a sequence of bytes from the current stream and advances the position within the stream by the number of bytes read.
		/// </summary>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		/// <returns></returns>
		public override int Read(byte[] buffer, int offset, int count)
		{
			return EndRead(BeginRead(buffer, offset, count, null, null));
		}

		/// <summary>
		/// Begins an asynchronous read operation.
		/// </summary>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		/// <param name="asyncCallback"></param>
		/// <param name="asyncState"></param>
		/// <returns></returns>
		public override IAsyncResult BeginRead(
			byte[] buffer,
			int offset,
			int count,
			AsyncCallback asyncCallback,
			Object asyncState)
		{
			TestConnectionIsValid();

			return sslStream.BeginRead(buffer, offset, count, asyncCallback, asyncState);
		}

		/// <summary>
		/// Waits for the pending asynchronous read to complete.
				/// </summary>
		/// <param name="asyncResult"></param>
		/// <returns></returns>
		public override int EndRead(IAsyncResult asyncResult)
		{
			TestConnectionIsValid();

			return sslStream.EndRead(asyncResult);
		}

		/// <summary>
		/// Not supported
		/// </summary>
		/// <param name="offset"></param>
		/// <param name="origin"></param>
		/// <returns></returns>
		public override long Seek(long offset, System.IO.SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		/// <summary>
		/// Sets the length of the current stream.
		/// </summary>
		/// <param name="value"></param>
		public override void SetLength(long value)
		{
			InnerStream.SetLength(value);
		}

		/// <summary>
		/// Writes a sequence of bytes to the current stream and advances the current position within this stream by the number of bytes written.
		/// </summary>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		public override void Write(byte[] buffer, int offset, int count)
		{
			TestConnectionIsValid();

			EndWrite(BeginWrite(buffer, offset, count, null, null));
		}

		/// <summary>
		/// Begins an asynchronous write operation.
		/// </summary>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		/// <param name="asyncCallback"></param>
		/// <param name="asyncState"></param>
		/// <returns></returns>
		public override IAsyncResult BeginWrite(
			byte[] buffer,
			int offset,
			int count,
			AsyncCallback asyncCallback,
			Object asyncState)
		{
			TestConnectionIsValid();

			return sslStream.BeginWrite(buffer, offset, count, asyncCallback, asyncState);
		}

		/// <summary>
		/// Ends an asynchronous write operation.
		/// </summary>
		/// <param name="asyncResult"></param>
		public override void EndWrite(IAsyncResult asyncResult)
		{
			TestConnectionIsValid();

			sslStream.EndWrite(asyncResult);
		}

		/// <summary>
		/// Closes the current stream and releases any resources (such as sockets and file handles) associated with the current stream.		
		/// </summary>
		public override void Close()
		{
			TestConnectionIsValid();

			base.Close();
			sslStream.Close();
		}
		#endregion

		#region Properties

		/// <summary>
		/// 
		/// </summary>
		public bool CheckCertificateRevocationStatus
		{
			get
			{
				if (!IsAuthenticated)
					return false;
				return sslStream.CheckCertificateRevocationStatus;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public CipherAlgorithmType CipherAlgorithm
		{
			get
			{
				if (!IsAuthenticated)
					return CipherAlgorithmType.None;
				return sslStream.CipherAlgorithm;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public int CipherStrength
		{
			get
			{
				if (!IsAuthenticated)
					return 0;
				return sslStream.CipherStrength;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public HashAlgorithmType HashAlgorithm
		{
			get
			{
				if (!IsAuthenticated)
					return HashAlgorithmType.None;
				return sslStream.HashAlgorithm;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public int HashStrength
		{
			get
			{
				if (!IsAuthenticated)
					return 0;
				return sslStream.HashStrength;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public ExchangeAlgorithmType KeyExchangeAlgorithm
		{
			get
			{
				if (!IsAuthenticated)
					return ExchangeAlgorithmType.None;
				return sslStream.KeyExchangeAlgorithm;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public int KeyExchangeStrength
		{
			get
			{
				if (!IsAuthenticated)
					return 0;
				return sslStream.KeyExchangeStrength;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public X509Certificate LocalCertificate
		{
			get
			{
				if (!IsAuthenticated)
					return null;
				return sslStream.LocalCertificate;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public virtual X509Certificate RemoteCertificate
		{
			get
			{
				if (!IsAuthenticated)
					return null;
				return sslStream.RemoteCertificate;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public SslProtocols SslProtocol
		{
			get
			{
				if (!IsAuthenticated)
					return SslProtocols.None;
				return sslStream.SslProtocol;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		public List<string> CipherList
		{
			get { return sslStream.CipherList; }
		}

		#endregion //Properties

		#region Methods
		/// <summary>
		/// 
		/// </summary>
		/// <param name="targetHost"></param>
		public virtual void AuthenticateAsClient(string targetHost)
		{
			AuthenticateAsClient(targetHost, null, null, SslProtocols.Default, SslStrength.Medium, false);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="targetHost"></param>
		/// <param name="certificates"></param>
		/// <param name="caCertificates"></param>
		/// <param name="enabledSslProtocols"></param>
		/// <param name="sslStrength"></param>
		/// <param name="checkCertificateRevocation"></param>
		public virtual void AuthenticateAsClient(
			string targetHost,
			X509List certificates,
			X509Chain caCertificates,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocation)
		{
			EndAuthenticateAsClient(BeginAuthenticateAsClient(targetHost, certificates, caCertificates, enabledSslProtocols, sslStrength, checkCertificateRevocation, null, null));
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="targetHost"></param>
		/// <param name="asyncCallback"></param>
		/// <param name="asyncState"></param>
		/// <returns></returns>
		public virtual IAsyncResult BeginAuthenticateAsClient(string targetHost, AsyncCallback asyncCallback, Object asyncState)
		{
			return BeginAuthenticateAsClient(targetHost, null, null, SslProtocols.Default, SslStrength.Medium, false, asyncCallback, asyncState);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="targetHost"></param>
		/// <param name="clientCertificates"></param>
		/// <param name="caCertificates"></param>
		/// <param name="enabledSslProtocols"></param>
		/// <param name="sslStrength"></param>
		/// <param name="checkCertificateRevocation"></param>
		/// <param name="asyncCallback"></param>
		/// <param name="asyncState"></param>
		/// <returns></returns>
		public virtual IAsyncResult BeginAuthenticateAsClient(
			string targetHost,
			X509List clientCertificates,
			X509Chain caCertificates,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocation,
			AsyncCallback asyncCallback,
			Object asyncState)
		{
			if (IsAuthenticated)
			{
				throw new InvalidOperationException("SslStream is already authenticated");
			}

			// Create the stream
			SslStreamClient client_stream = new SslStreamClient(InnerStream, false, targetHost, clientCertificates, caCertificates, enabledSslProtocols, sslStrength, checkCertificateRevocation, remoteCertificateValidationCallback, localCertificateSelectionCallback);
			// set the internal stream
			sslStream = client_stream;
			// start the write operation
			return BeginWrite(new byte[0], 0, 0, asyncCallback, asyncState);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="ar"></param>
		public virtual void EndAuthenticateAsClient(IAsyncResult ar)
		{
			TestConnectionIsValid();

			// Finish the async authentication.  The EndRead/EndWrite will complete successfully, or throw exception
			EndWrite(ar);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="serverCertificate"></param>
		public virtual void AuthenticateAsServer(X509Certificate serverCertificate)
		{
			AuthenticateAsServer(serverCertificate, false, null, SslProtocols.Default, SslStrength.Medium, false);
		}

		/// <summary>
		///
		/// </summary>
		/// <param name="serverCertificate"></param>
		/// <param name="clientCertificateRequired"></param>
		/// <param name="caCertificates"></param>
		/// <param name="enabledSslProtocols"></param>
		/// <param name="sslStrength"></param>
		/// <param name="checkCertificateRevocation"></param>
		public virtual void AuthenticateAsServer(
			X509Certificate serverCertificate,
			bool clientCertificateRequired,
			X509Chain caCertificates,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocation)
		{
			EndAuthenticateAsServer(BeginAuthenticateAsServer(serverCertificate, clientCertificateRequired, caCertificates, enabledSslProtocols, sslStrength, checkCertificateRevocation, null, null));
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="serverCertificate"></param>
		/// <param name="asyncCallback"></param>
		/// <param name="asyncState"></param>
		/// <returns></returns>
		public virtual IAsyncResult BeginAuthenticateAsServer(
			X509Certificate serverCertificate,
			AsyncCallback asyncCallback,
			Object asyncState)
		{
			return BeginAuthenticateAsServer(serverCertificate, false, null, SslProtocols.Default, SslStrength.Medium, false, asyncCallback, asyncState);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="serverCertificate"></param>
		/// <param name="clientCertificateRequired"></param>
		/// <param name="caCerts"></param>
		/// <param name="enabledSslProtocols"></param>
		/// <param name="sslStrength"></param>
		/// <param name="checkCertificateRevocation"></param>
		/// <param name="asyncCallback"></param>
		/// <param name="asyncState"></param>
		/// <returns></returns>
		public virtual IAsyncResult BeginAuthenticateAsServer(
			X509Certificate serverCertificate,
			bool clientCertificateRequired,
			X509Chain caCerts,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocation,
			AsyncCallback asyncCallback,
			Object asyncState)
		{
			if (IsAuthenticated)
			{
				throw new InvalidOperationException("SslStream is already authenticated");
			}
			// Initialize the server stream
			SslStreamServer server_stream = new SslStreamServer(InnerStream, false, serverCertificate, clientCertificateRequired, caCerts, enabledSslProtocols, sslStrength, checkCertificateRevocation, remoteCertificateValidationCallback);
			// Set the internal sslStream
			sslStream = server_stream;
			// Start the read operation
			return BeginRead(new byte[0], 0, 0, asyncCallback, asyncState);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="ar"></param>
		public virtual void EndAuthenticateAsServer(IAsyncResult ar)
		{
			TestConnectionIsValid();

			// Finish the async AuthenticateAsServer call - EndRead/Write call will throw exception on error
			EndRead(ar);
		}

		/// <summary>
		/// 
		/// </summary>
		public void Renegotiate()
		{
			TestConnectionIsValid();

			EndRenegotiate(BeginRenegotiate(null, null));
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="callback"></param>
		/// <param name="state"></param>
		/// <returns></returns>
		public IAsyncResult BeginRenegotiate(AsyncCallback callback, object state)
		{
			TestConnectionIsValid();

			sslStream.Renegotiate();

			if (sslStream is SslStreamClient)
			{
				return BeginWrite(new byte[0], 0, 0, callback, state);
			}
			else
			{
				return BeginRead(new byte[0], 0, 0, callback, state);
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="asyncResult"></param>
		public void EndRenegotiate(IAsyncResult asyncResult)
		{
			TestConnectionIsValid();

			if (sslStream is SslStreamClient)
			{
				EndWrite(asyncResult);
			}
			else
			{
				EndRead(asyncResult);
			}
		}

		#endregion

		#region Helpers
		private void TestConnectionIsValid()
		{
			if (sslStream == null)
			{
				throw new InvalidOperationException("SslStream has not been authenticated");
			}
		}
		#endregion

		#region Fields
		SslStreamBase sslStream;
		internal RemoteCertificateValidationHandler remoteCertificateValidationCallback = null;
		internal LocalCertificateSelectionHandler localCertificateSelectionCallback = null;
		internal bool m_bCheckCertRevocationStatus = false;
		#endregion
	}
}
