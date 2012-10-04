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
using System.Threading;
using OpenSSL.Core;
using OpenSSL.X509;

namespace OpenSSL.SSL
{
	internal abstract class SslStreamBase : Stream, IDisposable
	{
		internal Stream innerStream;
		internal bool ownStream;
		private volatile bool disposed = false;
		internal SslContext sslContext;
		internal Ssl ssl;
		internal BIO read_bio;
		internal BIO write_bio;
		private byte[] read_buffer; // for reading from the stream
		private MemoryStream decrypted_data_stream; // decrypted data from Ssl.Read
		//private volatile bool inHandshakeLoop;
		private const int SSL3_RT_HEADER_LENGTH = 5;
		private const int SSL3_RT_MAX_PLAIN_LENGTH = 16384;
		private const int SSL3_RT_MAX_COMPRESSED_LENGTH = (1024 + SSL3_RT_MAX_PLAIN_LENGTH);
		private const int SSL3_RT_MAX_ENCRYPTED_LENGTH = (1024 + SSL3_RT_MAX_COMPRESSED_LENGTH);
		private const int SSL3_RT_MAX_PACKET_SIZE = (SSL3_RT_MAX_ENCRYPTED_LENGTH + SSL3_RT_HEADER_LENGTH);
		private const int WaitTimeOut = 300 * 1000; // 5 minutes
		protected LocalCertificateSelectionHandler localCertificateSelectionCallback;
		protected RemoteCertificateValidationHandler remoteCertificateSelectionCallback;
		protected bool checkCertificateRevocationStatus = false;
		protected HandshakeState handShakeState = HandshakeState.None;
		protected OpenSslException handshakeException = null;

		/// <summary>
		/// Override to implement client/server specific handshake processing
		/// </summary>
		/// <returns></returns>
		internal protected abstract bool ProcessHandshake();

		#region InternalAsyncResult class

		private class InternalAsyncResult : IAsyncResult
		{
			private object locker = new object();
			private AsyncCallback userCallback;
			private object userState;
			private Exception asyncException;
			private ManualResetEvent asyncWaitHandle;
			private bool isCompleted;
			private int bytesRead;
			private bool isWriteOperation;
			private bool continueAfterHandshake;

			private byte[] buffer;
			private int offset;
			private int count;

			public InternalAsyncResult(AsyncCallback userCallback, object userState, byte[] buffer, int offset, int count, bool isWriteOperation, bool continueAfterHandshake)
			{
				this.userCallback = userCallback;
				this.userState = userState;
				this.buffer = buffer;
				this.offset = offset;
				this.count = count;
				this.isWriteOperation = isWriteOperation;
				this.continueAfterHandshake = continueAfterHandshake;
			}

			public bool ContinueAfterHandshake
			{
				get { return this.continueAfterHandshake; }
			}

			public bool IsWriteOperation
			{
				get { return this.isWriteOperation; }
				set { this.isWriteOperation = value; }
			}

			public byte[] Buffer
			{
				get { return this.buffer; }
			}

			public int Offset
			{
				get { return this.offset; }
			}

			public int Count
			{
				get { return this.count; }
			}

			public int BytesRead
			{
				get { return this.bytesRead; }
			}

			public object AsyncState
			{
				get { return this.userState; }
			}

			public Exception AsyncException
			{
				get { return this.asyncException; }
			}

			public bool CompletedWithError
			{
				get
				{
					if (IsCompleted == false)
					{
						return false;
					}
					return (null != asyncException);
				}
			}

			public WaitHandle AsyncWaitHandle
			{
				get
				{
					lock (locker)
					{
						// Create the event if we haven't already done so
						if (this.asyncWaitHandle == null)
						{
							this.asyncWaitHandle = new ManualResetEvent(isCompleted);
						}
					}
					return this.asyncWaitHandle;
				}
			}

			public bool CompletedSynchronously
			{
				get { return false; }
			}

			public bool IsCompleted
			{
				get
				{
					lock (locker)
					{
						return this.isCompleted;
					}
				}
			}

			private void SetComplete(Exception ex, int bytesRead)
			{
				lock (locker)
				{
					if (this.isCompleted)
					{
						return;
					}

					this.isCompleted = true;
					this.asyncException = ex;
					this.bytesRead = bytesRead;
					// If the wait handle isn't null, we should set the event
					// rather than fire a callback
					if (this.asyncWaitHandle != null)
					{
						this.asyncWaitHandle.Set();
					}
				}
				// If we have a callback method, invoke it
				if (this.userCallback != null)
				{
					this.userCallback.BeginInvoke(this, null, null);
				}
			}

			public void SetComplete(Exception ex)
			{
				SetComplete(ex, 0);
			}

			public void SetComplete(int bytesRead)
			{
				SetComplete(null, bytesRead);
			}

			public void SetComplete()
			{
				SetComplete(null, 0);
			}
		}
		#endregion

		public SslStreamBase(Stream stream, bool ownStream)
		{
			if (stream == null)
			{
				throw new ArgumentNullException("stream");
			}
			if (!stream.CanRead || !stream.CanWrite)
			{
				throw new ArgumentException("Stream must allow read and write capabilities", "stream");
			}
			innerStream = stream;
			this.ownStream = ownStream;
			read_buffer = new byte[16384];
			//inHandshakeLoop = false;
			decrypted_data_stream = new MemoryStream();
		}

		public bool HandshakeComplete
		{
			get { return handShakeState == HandshakeState.Complete; }
		}

		private bool NeedHandshake
		{
			get { return ((handShakeState == HandshakeState.None) || (handShakeState == HandshakeState.Renegotiate)); }
		}

		public bool CheckCertificateRevocationStatus
		{
			get { return checkCertificateRevocationStatus; }
			set { checkCertificateRevocationStatus = value; }
		}

		public LocalCertificateSelectionHandler LocalCertSelectionCallback
		{
			get { return localCertificateSelectionCallback; }
			set { localCertificateSelectionCallback = value; }
		}

		public RemoteCertificateValidationHandler RemoteCertValidationCallback
		{
			get { return remoteCertificateSelectionCallback; }
			set { remoteCertificateSelectionCallback = value; }
		}

		public X509Certificate LocalCertificate
		{
			get { return ssl.LocalCertificate; }
		}

		public X509Certificate RemoteCertificate
		{
			get { return ssl.RemoteCertificate; }
		}

		public CipherAlgorithmType CipherAlgorithm
		{
			get { return ssl.CurrentCipher.CipherAlgorithm; }
		}

		public int CipherStrength
		{
			get { return ssl.CurrentCipher.Strength; }
		}

		public HashAlgorithmType HashAlgorithm
		{
			get { return ssl.CurrentCipher.HashAlgorithm; }
		}

		public int HashStrength
		{
			get
			{
				switch (HashAlgorithm)
				{
					case HashAlgorithmType.Md5:
						return 128;
					case HashAlgorithmType.Sha1:
						return 160;
					default:
						return 0;
				}
			}
		}

		public ExchangeAlgorithmType KeyExchangeAlgorithm
		{
			get { return ssl.CurrentCipher.KeyExchangeAlgorithm; }
		}

		public int KeyExchangeStrength
		{
			get { return ssl.CurrentCipher.KeyExchangeStrength; }
		}

		public SslProtocols SslProtocol
		{
			get { return ssl.CurrentCipher.SslProtocol; }
		}

		public List<string> CipherList
		{
			get { return sslContext.GetCipherList(); }
		}

		#region Stream methods
		public override bool CanRead
		{
			get { return innerStream.CanRead; }
		}

		public override bool CanSeek
		{
			get { return innerStream.CanSeek; }
		}

		public override bool CanWrite
		{
			get { return innerStream.CanWrite; }
		}

		public override void Flush()
		{
			if (disposed)
			{
				throw new ObjectDisposedException("SslStreamBase");
			}
			innerStream.Flush();
		}

		public override long Length
		{
			get { return innerStream.Length; }
		}

		public override long Position
		{
			get { return innerStream.Position; }
			set { throw new NotSupportedException(); }
		}

		public override int ReadTimeout
		{
			get { return innerStream.ReadTimeout; }
			set { innerStream.ReadTimeout = value; }
		}

		public override int WriteTimeout
		{
			get { return innerStream.WriteTimeout; }
			set { innerStream.WriteTimeout = value; }
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotImplementedException();
		}

		public override void SetLength(long value)
		{
			innerStream.SetLength(value);
		}

		//!! - not implementing blocking read, but using BeginRead with no callbacks
		public override int Read(byte[] buffer, int offset, int count)
		{
			throw new NotImplementedException();
		}
		/*
		public override int Read(byte[] buffer, int offset, int count)
		{
			// Check to see if we need to reset the decrypted data stream
			if (decrypted_data_stream.Position == decrypted_data_stream.Length)
			{
				// reset the stream
				decrypted_data_stream.Seek(0, SeekOrigin.Begin);
				decrypted_data_stream.SetLength(0);
			}
			// Check to see if we have data in the decrypted memory stream, if so return it
			if (decrypted_data_stream.Position > 0 && (decrypted_data_stream.Position != decrypted_data_stream.Length))
			{
				return decrypted_data_stream.Read(buffer, offset, count);
			}
            
			// No pre-existing data in the stream, read from the innerStream
			int bytesRead = 0;
			bool haveDataToReturn = false;

			while (! haveDataToReturn)
			{
				try
				{
					bytesRead = innerStream.Read(read_buffer, 0, read_buffer.Length);
				}
				catch(System.IO.IOException ex)
				{
					//!!TODO - log exception
					return 0;
				}
				// if we have data, let's process it
				if (bytesRead > 0)
				{
					// Copy encrypted data into the SSL read_bio
					read_bio.Write(read_buffer, bytesRead);
					if (inHandshakeLoop)
					{
						if (ProcessHandshake())
						{
							inHandshakeLoop = false;
						}
					}
					//!!else -- Process data in read_bio after handshake if there is any
					{
						uint nBytesPending = read_bio.BytesPending;
						byte[] decrypted_buf = new byte[SSL3_RT_MAX_PACKET_SIZE];
						while (nBytesPending > 0)
						{
							int decryptedBytesRead = ssl.Read(decrypted_buf, decrypted_buf.Length);
							if (decryptedBytesRead <= 0)
							{
								SslError lastError = ssl.GetError(decryptedBytesRead);
								if (lastError == SslError.SSL_ERROR_WANT_READ)
								{
									// Renogiated requested by the client
									if (write_bio.BytesPending > 0)
									{
										inHandshakeLoop = true;
										if (ProcessHandshake())
										{
											inHandshakeLoop = false;
										}
									}
									//!!break; -- continue processing the handshake data
								}
								else if (lastError == SslError.SSL_ERROR_WANT_WRITE)
								{
									// unexpected error!
									//!!TODO debug log
								}
								else if (lastError == SslError.SSL_ERROR_ZERO_RETURN)
								{
									// Shutdown alert
									SendShutdownAlert();
									break;
								}
								else
								{
									//!!TODO - log last error, throw expection
									break;
								}
							}
							// Write decrypted data to memory stream
							long pos = decrypted_data_stream.Position;
							decrypted_data_stream.Seek(0, SeekOrigin.End);
							decrypted_data_stream.Write(decrypted_buf, 0, decrypted_buf.Length);
							decrypted_data_stream.Seek(pos, SeekOrigin.Begin);
							haveDataToReturn = true;

							// See if we have more data to process
							nBytesPending = read_bio.BytesPending;
						}
					}
				}
			}
			// Read data from the decrypted data stream into the user buffer
			return decrypted_data_stream.Read(buffer, offset, count);
		}
		*/

		public void SendShutdownAlert()
		{
			int nShutdownRet = ssl.Shutdown();
			if (nShutdownRet == 0)
			{
				uint nBytesToWrite = write_bio.BytesPending;
				if (nBytesToWrite <= 0)
				{
					// unexpected error
					//!!TODO log error
					return;
				}
				ArraySegment<byte> buf = write_bio.ReadBytes((int)nBytesToWrite);
				if (buf.Count <= 0)
				{
					//!!TODO - log error
				}
				else
				{
					// Write the shutdown alert to the stream
					innerStream.Write(buf.Array, 0, buf.Count);
				}
			}
		}

		public override IAsyncResult BeginRead(
			byte[] buffer,
			int offset,
			int count,
			AsyncCallback asyncCallback,
			object asyncState)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException("buffer", "buffer can't be null");
			}
			if (offset < 0)
			{
				throw new ArgumentOutOfRangeException("offset", "offset less than 0");
			}
			if (offset > buffer.Length)
			{
				throw new ArgumentOutOfRangeException("offset", "offset must be less than buffer length");
			}
			if (count < 0)
			{
				throw new ArgumentOutOfRangeException("count", "count less than 0");
			}
			if (count > (buffer.Length - offset))
			{
				throw new ArgumentOutOfRangeException("count", "count is greater than buffer length - offset");
			}

			bool proceedAfterHandshake = true;
			if (count == 0) proceedAfterHandshake = false;

			InternalAsyncResult internalAsyncResult = new InternalAsyncResult(asyncCallback, asyncState, buffer, offset, count, false, proceedAfterHandshake);

			if (NeedHandshake)
			{
				//inHandshakeLoop = true;
				BeginHandshake(internalAsyncResult);
			}
			else
			{
				InternalBeginRead(internalAsyncResult);
			}

			return internalAsyncResult;
		}

		private void InternalBeginRead(InternalAsyncResult asyncResult)
		{
			// Check to see if the decrypted data stream should be reset
			if (decrypted_data_stream.Position == decrypted_data_stream.Length)
			{
				decrypted_data_stream.Seek(0, SeekOrigin.Begin);
				decrypted_data_stream.SetLength(0);
			}
			// Check to see if we have data waiting in the decrypted data stream
			if (decrypted_data_stream.Length > 0 && (decrypted_data_stream.Position != decrypted_data_stream.Length))
			{
				// Process the pre-existing data
				int bytesRead = decrypted_data_stream.Read(asyncResult.Buffer, asyncResult.Offset, asyncResult.Count);
				asyncResult.SetComplete(bytesRead);
				return;
			}
			// Start the async read from the inner stream
			innerStream.BeginRead(read_buffer, 0, read_buffer.Length, new AsyncCallback(InternalReadCallback), asyncResult);
		}

		private void InternalReadCallback(IAsyncResult asyncResult)
		{
			InternalAsyncResult internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;
			bool haveDataToReturn = false;

			try
			{
				int bytesRead = 0;
				try
				{
					bytesRead = innerStream.EndRead(asyncResult);
				}
				catch (Exception ex)
				{
					// Set the exception into the internal async result
					internalAsyncResult.SetComplete(ex);
				}
				if (bytesRead <= 0)
				{
					// Zero byte read most likely indicates connection closed (if it's a network stream)
					internalAsyncResult.SetComplete(0);
					return;
				}
				else
				{
					// Copy encrypted data into the SSL read_bio
					read_bio.Write(read_buffer, bytesRead);
					if (handShakeState == HandshakeState.InProcess ||
						handShakeState == HandshakeState.RenegotiateInProcess)
					{
						// We are in the handshake, complete the async operation to fire the async
						// handshake callback for processing
						internalAsyncResult.SetComplete(bytesRead);
						return;
					}
					uint nBytesPending = read_bio.BytesPending;
					byte[] decrypted_buf = new byte[SSL3_RT_MAX_PACKET_SIZE];
					while (nBytesPending > 0)
					{
						int decryptedBytesRead = ssl.Read(decrypted_buf, decrypted_buf.Length);
						if (decryptedBytesRead <= 0)
						{
							SslError lastError = ssl.GetError(decryptedBytesRead);
							if (lastError == SslError.SSL_ERROR_WANT_READ)
							{
								// if we have bytes pending in the write bio.
								// the client has requested a renegotiation
								if (write_bio.BytesPending > 0)
								{
									// Start the renegotiation by writing the write_bio data, and use the RenegotiationWriteCallback
									// to handle the rest of the renegotiation
									ArraySegment<byte> buf = write_bio.ReadBytes((int)write_bio.BytesPending);
									innerStream.BeginWrite(buf.Array, 0, buf.Count, new AsyncCallback(RenegotiationWriteCallback), internalAsyncResult);
									return;
								}
								// no data in the out bio, we just need more data to complete the record
								//break;
							}
							else if (lastError == SslError.SSL_ERROR_WANT_WRITE)
							{
								// unexpected error!
								//!!TODO debug log
							}
							else if (lastError == SslError.SSL_ERROR_ZERO_RETURN)
							{
								// Shutdown alert
								SendShutdownAlert();
								break;
							}
							else
							{
								throw new OpenSslException();
							}
						}
						if (decryptedBytesRead > 0)
						{
							// Write decrypted data to memory stream
							long pos = decrypted_data_stream.Position;
							decrypted_data_stream.Seek(0, SeekOrigin.End);
							decrypted_data_stream.Write(decrypted_buf, 0, decryptedBytesRead);
							decrypted_data_stream.Seek(pos, SeekOrigin.Begin);
							haveDataToReturn = true;
						}

						// See if we have more data to process
						nBytesPending = read_bio.BytesPending;
					}
					// Check to see if we have data to return, if not, fire the async read again
					if (!haveDataToReturn)
					{
						innerStream.BeginRead(read_buffer, 0, read_buffer.Length, new AsyncCallback(InternalReadCallback), internalAsyncResult);
					}
					else
					{
						int bytesReadIntoUserBuffer = 0;

						// Read the data into the buffer provided by the user (now hosted in the InternalAsyncResult)
						bytesReadIntoUserBuffer = decrypted_data_stream.Read(internalAsyncResult.Buffer, internalAsyncResult.Offset, internalAsyncResult.Count);

						internalAsyncResult.SetComplete(bytesReadIntoUserBuffer);
					}
				}
			}
			catch (Exception ex)
			{
				internalAsyncResult.SetComplete(ex);
			}
		}

		public override int EndRead(IAsyncResult asyncResult)
		{
			InternalAsyncResult internalAsyncResult = asyncResult as InternalAsyncResult;
			if (internalAsyncResult == null)
			{
				throw new ArgumentException("AsyncResult was not obtained via BeginRead", "asyncResult");
			}
			// Check to see if the operation is complete, if not -- let's wait for it
			if (!internalAsyncResult.IsCompleted)
			{
				if (!internalAsyncResult.AsyncWaitHandle.WaitOne(WaitTimeOut, false))
				{
					throw new IOException("Failed to complete read operation");
				}
			}

			// If we completed with an error, throw the exceptions
			if (internalAsyncResult.CompletedWithError)
			{
				throw internalAsyncResult.AsyncException;
			}

			// Success, return the bytes read
			return internalAsyncResult.BytesRead;
		}

		//!! - not implmenting blocking Write, use BeginWrite with no callback
		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotImplementedException();
		}
		/*
		public override void Write(byte[] buffer, int offset, int count)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException("buffer");
			}
			if (offset < 0)
			{
				throw new ArgumentOutOfRangeException("offset", "Offset must be greater than or equal to 0");
			}
			if (offset > buffer.Length)
			{
				throw new ArgumentOutOfRangeException("offset", "Offset is greater than length of the buffer");
			}
			if (count < 0)
			{
				throw new ArgumentOutOfRangeException("count", "Count must be greater than 0");    
			}
			if (count > (buffer.Length - offset))
			{
				throw new ArgumentOutOfRangeException("count", "Count is greater than buffer length - offset");
			}

			byte[] new_buffer = buffer;
			if (offset != 0)
			{
				byte[] temp = new byte[count];
				Array.Copy(buffer, offset, temp, 0, count);
				new_buffer = temp;
			}

			int bytesWritten = ssl.Write(new_buffer, count);
			if (bytesWritten <= 0)
			{
				SslError lastError = ssl.GetError(bytesWritten);
				if (lastError == SslError.SSL_ERROR_WANT_READ)
				{
					//!!TODO - Log - unexpected renogiation request
				}
				throw new OpenSslException((uint)lastError);
			}
			uint bytesPending = write_bio.BytesPending;
			while (bytesPending > 0)
			{
				ArraySegment<byte> buf = write_bio.ReadBytes((int)bytesPending);
				innerStream.Write(buf.Array, 0, buf.Count);
				bytesPending = write_bio.BytesPending;
			}
		}
		*/

		public override IAsyncResult BeginWrite(
			byte[] buffer,
			int offset,
			int count,
			AsyncCallback asyncCallback,
			object asyncState)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException("buffer", "buffer can't be null");
			}
			if (offset < 0)
			{
				throw new ArgumentOutOfRangeException("offset", "offset less than 0");
			}
			if (offset > buffer.Length)
			{
				throw new ArgumentOutOfRangeException("offset", "offset must be less than buffer length");
			}
			if (count < 0)
			{
				throw new ArgumentOutOfRangeException("count", "count less than 0");
			}
			if (count > (buffer.Length - offset))
			{
				throw new ArgumentOutOfRangeException("count", "count is greater than buffer length - offset");
			}

			bool proceedAfterHandshake = true;
			if (count == 0) proceedAfterHandshake = false;

			InternalAsyncResult asyncResult = new InternalAsyncResult(asyncCallback, asyncState, buffer, offset, count, true, proceedAfterHandshake);

			if (NeedHandshake)
			{
				//inHandshakeLoop = true;
				// Start the handshake
				BeginHandshake(asyncResult);
			}
			else
			{
				InternalBeginWrite(asyncResult);
			}

			return asyncResult;
		}

		private void InternalBeginWrite(InternalAsyncResult asyncResult)
		{
			byte[] new_buffer = asyncResult.Buffer;

			if (asyncResult.Offset != 0 && asyncResult.Count != 0)
			{
				new_buffer = new byte[asyncResult.Count];
				Array.Copy(asyncResult.Buffer, asyncResult.Offset, new_buffer, 0, asyncResult.Count);
			}

			// Only write to the SSL object if we have data
			if (asyncResult.Count != 0)
			{
				int bytesWritten = ssl.Write(new_buffer, asyncResult.Count);
				if (bytesWritten < 0)
				{
					SslError lastError = ssl.GetError(bytesWritten);
					if (lastError == SslError.SSL_ERROR_WANT_READ)
					{
						//!!TODO - Log - unexpected renogiation request
					}
					throw new OpenSslException();
				}
			}
			uint bytesPending = write_bio.BytesPending;
			//!!while (bytesPending > 0)
			{
				ArraySegment<byte> buf = write_bio.ReadBytes((int)bytesPending);
				innerStream.BeginWrite(buf.Array, 0, buf.Count, new AsyncCallback(InternalWriteCallback), asyncResult);
				//!!bytesPending = write_bio.BytesPending;
			}
		}

		private void InternalWriteCallback(IAsyncResult asyncResult)
		{
			InternalAsyncResult internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;

			try
			{
				innerStream.EndWrite(asyncResult);
				internalAsyncResult.SetComplete();
			}
			catch (Exception ex)
			{
				internalAsyncResult.SetComplete(ex);
			}
		}

		public override void EndWrite(IAsyncResult asyncResult)
		{
			InternalAsyncResult internalAsyncResult = asyncResult as InternalAsyncResult;

			if (internalAsyncResult == null)
			{
				throw new ArgumentException("AsyncResult object was not obtained from SslStream.BeginWrite", "asyncResult");
			}

			if (!internalAsyncResult.IsCompleted)
			{
				if (!internalAsyncResult.AsyncWaitHandle.WaitOne(WaitTimeOut, false))
				{
					throw new IOException("Failed to complete the Write operation");
				}
			}

			if (internalAsyncResult.CompletedWithError)
			{
				throw internalAsyncResult.AsyncException;
			}
		}

		private void RenegotiationWriteCallback(IAsyncResult asyncResult)
		{
			InternalAsyncResult readwriteAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;

			innerStream.EndWrite(asyncResult);

			// Now start the read with the original asyncresult, as the ssl.Read will handle the renegoiation
			InternalBeginRead(readwriteAsyncResult);
		}

		/*
		public abstract virtual bool ProcessRenegotiation();

		private IAsyncResult BeginRenegotiate(InternalAsyncResult readwriteAsyncResult)
		{
			Console.WriteLine("BeginRenegotiate");

			handShakeState = HandshakeState.Renegotiate;

			// Wrap the readwriteAsyncResult in the renegotiateAsyncResult
			InternalAsyncResult renegotiateAsyncResult = new InternalAsyncResult(new AsyncCallback(RenegotiateComplete), readwriteAsyncResult, null, 0, 0, readwriteAsyncResult.IsWriteOperation, readwriteAsyncResult.ContinueAfterHandshake);

			if (ProcessRenegotiation())
			{
				handShakeState = HandshakeState.Complete;
				renegotiateAsyncResult.SetComplete();
			}
			else
			{
				//!! if (readwriteAsyncResult.IsWriteOperation)
				if (write_bio.BytesPending > 0)
				{
					renegotiateAsyncResult.IsWriteOperation = true;
					BeginWrite(new byte[0], 0, 0, new AsyncCallback(RenegotiateCallback), renegotiateAsyncResult);
				}
				else
				{
					renegotiateAsyncResult.IsWriteOperation = false;
					BeginRead(new byte[0], 0, 0, new AsyncCallback(RenegotiateCallback), renegotiateAsyncResult);
				}
			}
			return renegotiateAsyncResult;
		}

		private void RenegotiateCallback(IAsyncResult asyncResult)
		{
			InternalAsyncResult renegotiateAsyncResult = asyncResult.AsyncState as InternalAsyncResult;
		}
		*/

		private IAsyncResult BeginHandshake(InternalAsyncResult readwriteAsyncResult)
		{
			//!!
			// Move the handshake state to the next state
			//if (handShakeState == HandshakeState.Renegotiate)
			//{
			//    handShakeState = HandshakeState.RenegotiateInProcess;
			//}
			//else
			if (handShakeState != HandshakeState.Renegotiate)
			{
				handShakeState = HandshakeState.InProcess;
			}

			// Wrap the read/write InternalAsyncResult in the Handshake InternalAsyncResult instance
			InternalAsyncResult handshakeAsyncResult = new InternalAsyncResult(new AsyncCallback(AsyncHandshakeComplete), readwriteAsyncResult, null, 0, 0, readwriteAsyncResult.IsWriteOperation, readwriteAsyncResult.ContinueAfterHandshake);

			if (ProcessHandshake())
			{
				//inHandshakeLoop = false;
				handShakeState = HandshakeState.Complete;
				handshakeAsyncResult.SetComplete();
			}
			else
			{
				//!! if (readwriteAsyncResult.IsWriteOperation)
				if (write_bio.BytesPending > 0)
				{
					handshakeAsyncResult.IsWriteOperation = true;
					BeginWrite(new byte[0], 0, 0, new AsyncCallback(AsyncHandshakeCallback), handshakeAsyncResult);
				}
				else
				{
					handshakeAsyncResult.IsWriteOperation = false;
					BeginRead(new byte[0], 0, 0, new AsyncCallback(AsyncHandshakeCallback), handshakeAsyncResult);
				}
			}
			return handshakeAsyncResult;
		}

		private void AsyncHandshakeCallback(IAsyncResult asyncResult)
		{
			// Get the handshake internal result instance
			InternalAsyncResult internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;
			int bytesRead = 0;

			if (internalAsyncResult.IsWriteOperation)
			{
				EndWrite(asyncResult);
				// Check to see if the handshake is complete (this could have been
				// the last response packet from the server.  If so, we want to finalize
				// the async operation and call the HandshakeComplete callback
				if (handShakeState == HandshakeState.Complete)
				{
					internalAsyncResult.SetComplete();
					return;
				}
				// Check to see if we saved an exception from the last Handshake process call
				// the if the client gets an error code, it needs to send the alert, and then
				// throw the exception here.
				if (handshakeException != null)
				{
					internalAsyncResult.SetComplete(handshakeException);
					return;
				}
				// We wrote out the handshake data, now read to get the response
				internalAsyncResult.IsWriteOperation = false;
				BeginRead(new byte[0], 0, 0, new AsyncCallback(AsyncHandshakeCallback), internalAsyncResult);
			}
			else
			{
				try
				{
					bytesRead = EndRead(asyncResult);
					if (bytesRead > 0)
					{
						if (ProcessHandshake())
						{
							//inHandshakeLoop = false;
							handShakeState = HandshakeState.Complete;
							// We have completed the handshake, but need to send the
							// last response packet.
							if (write_bio.BytesPending > 0)
							{
								internalAsyncResult.IsWriteOperation = true;
								BeginWrite(new byte[0], 0, 0, new AsyncCallback(AsyncHandshakeCallback), internalAsyncResult);
							}
							else
							{
								internalAsyncResult.SetComplete();
								return;
							}
						}
						else
						{
							// Not complete with the handshake yet, write the handshake packet out
							internalAsyncResult.IsWriteOperation = true;
							BeginWrite(new byte[0], 0, 0, new AsyncCallback(AsyncHandshakeCallback), internalAsyncResult);
						}
					}
					else
					{
						// Read read 0 bytes, the remote socket has been closed, so complete the operation
						internalAsyncResult.SetComplete(new IOException("The remote stream has been closed"));
					}
				}
				catch (Exception ex)
				{
					internalAsyncResult.SetComplete(ex);
				}
			}
		}

		private void AsyncHandshakeComplete(IAsyncResult asyncResult)
		{
			EndHandshake(asyncResult);
		}

		private void EndHandshake(IAsyncResult asyncResult)
		{
			InternalAsyncResult handshakeAsyncResult = asyncResult as InternalAsyncResult;
			InternalAsyncResult readwriteAsyncResult = asyncResult.AsyncState as InternalAsyncResult;

			if (!handshakeAsyncResult.IsCompleted)
			{
				handshakeAsyncResult.AsyncWaitHandle.WaitOne(WaitTimeOut, false);
			}
			if (handshakeAsyncResult.CompletedWithError)
			{
				// if there's a handshake error, pass it to the read asyncresult instance
				readwriteAsyncResult.SetComplete(handshakeAsyncResult.AsyncException);
				return;
			}
			if (readwriteAsyncResult.ContinueAfterHandshake)
			{
				// We should continue the read/write operation since the handshake is complete
				if (readwriteAsyncResult.IsWriteOperation)
				{
					InternalBeginWrite(readwriteAsyncResult);
				}
				else
				{
					InternalBeginRead(readwriteAsyncResult);
				}
			}
			else
			{
				// If we aren't continuing, we're done
				readwriteAsyncResult.SetComplete();
			}
		}

		public override void Close()
		{
			//base.Close();
			if (ssl != null)
			{
				ssl.Dispose();
				ssl = null;
			}
			if (sslContext != null)
			{
				sslContext.Dispose();
				sslContext = null;
			}
		}

		#endregion

		/// <summary>
		/// Renegotiate session keys - calls SSL_renegotiate
		/// </summary>
		public void Renegotiate()
		{
			if (ssl != null)
			{
				// Call the SSL_renegotiate to reset the SSL object state
				// to start handshake
				Native.ExpectSuccess(Native.SSL_renegotiate(ssl.Handle));
				handShakeState = HandshakeState.Renegotiate;
			}
		}

		#region IDisposable Members

		void IDisposable.Dispose()
		{
			if (!disposed)
			{
			}
		}

		#endregion

		internal string GetCipherString(bool FIPSmode, SslProtocols sslProtocols, SslStrength sslStrength)
		{
			string str = "";

			if (FIPSmode || ((sslStrength & SslStrength.High) == SslStrength.High))
			{
				str = "HIGH";
			}
			if (FIPSmode || ((sslStrength & SslStrength.Medium) == SslStrength.Medium))
			{
				if (String.IsNullOrEmpty(str))
				{
					str = "MEDIUM";
				}
				else
				{
					str += ":MEDIUM";
				}
			}
			if (!FIPSmode && ((sslStrength & SslStrength.Low) == SslStrength.Low))
			{
				if (String.IsNullOrEmpty(str))
				{
					str = "LOW";
				}
				else
				{
					str += ":LOW";
				}
			}
			if ((sslProtocols == SslProtocols.Default) ||
				(sslProtocols == SslProtocols.Tls) ||
				(sslProtocols == SslProtocols.Ssl3))
			{
				if (String.IsNullOrEmpty(str))
				{
					str = "!SSLv2";
				}
				else
				{
					str += ":!SSLv2";
				}
			}
			if (FIPSmode)
			{
				str += ":AES:3DES:SHA:!DES:!MD5:!IDEA:!RC2:!RC4";
			}

			// Now format the return string
			return String.Format("{0}:!ADH:!aNULL:!eNULL:@STRENGTH", str);
		}

	}
}
