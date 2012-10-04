// Copyright (c) 2009 Ben Henderson
// Copyright (c) 2012 Frank Laub
// All rights reserved.
//
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
using System.Threading;
using System.Net;
using System.Net.Sockets;
using OpenSSL;
using OpenSSL.Core;
using OpenSSL.X509;
using OpenSSL.SSL;
using NUnit.Framework;

namespace UnitTests
{
	[TestFixture]
	public class TestServer : TestBase
	{
		public X509Chain serverCAChain = null;
		public X509Certificate serverCertificate = null;
		public X509List clientCertificateList = null;
		public X509Chain clientCAChain = null;

		private X509Certificate LoadPKCS12Certificate(string certFilename, string password) {
			using (BIO certFile = BIO.File(certFilename, "r")) {
				return X509Certificate.FromPKCS12(certFile, password);
			}
		}

		private X509Chain LoadCACertificateChain(string caFilename) {
			using (BIO bio = BIO.File(caFilename, "r")) {
				return new X509Chain(bio);
			}
		}

		/*
		 * Basic Client Server Tests
		 * 
		 * Test the default SslStream implementation in sync and async methods
		 *      No Server certificate verification
		 *      Default SSL protocols
		 *      
		 */
		public class SyncServerTests
		{
			protected TestServer testServer = null;
			protected byte[] clientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
			protected byte[] serverMessage = Encoding.ASCII.GetBytes("This is a message from the server");
			protected byte[] serverReadBuffer = new byte[256];
			protected byte[] clientReadBuffer = new byte[256];
			protected TcpListener listener = null;
			protected TcpClient client = null;
			protected SslStream sslStream = null;
			protected string testName = "Not set";
			protected RemoteCertificateValidationHandler clientRemoteCertificateValidationCallback = null;
			protected LocalCertificateSelectionHandler clientLocalCertificateSelectionCallback = null;
			protected RemoteCertificateValidationHandler serverRemoteCertificateValidationCallback = null;

			public SyncServerTests(TestServer testServer) {
				this.testServer = testServer;
			}

			#region BasicSyncServerTest
			public void BasicServerTest() {
				try {
					testName = "BasicServerTest";
					AcceptConnection(); // sets the client member
					sslStream = new SslStream(client.GetStream(), false);
					sslStream.AuthenticateAsServer(testServer.serverCertificate);
					// Do the server read, and write of the messages
					if (DoServerReadWrite()) {
						Shutdown(true);
					}
					else {
						Shutdown(false);
					}
				}
				catch (Exception) {
					Shutdown(false);
				}
			}

			#region IntermediateServerTest
			public void IntermediateServerTest() {
				try {
					testName = "IntermediateServerTest";
					AcceptConnection(); // sets the client member
					sslStream = new SslStream(client.GetStream(), false);
					sslStream.AuthenticateAsServer(testServer.serverCertificate, false, null, SslProtocols.Tls, SslStrength.All, false);

					// Verify protocol
					if (sslStream.SslProtocol != SslProtocols.Tls) {
						Console.WriteLine("{0} failed - negotiated non Tls connection", testName);
						Shutdown(false);
						return;
					}
					// Verify cipher strength
					if (sslStream.CipherStrength < 256) {
						Console.WriteLine("{0} failed - negotiated less than 256bit cipher", testName);
						Shutdown(false);
						return;
					}
					//Verify cipher
					if (sslStream.CipherAlgorithm != CipherAlgorithmType.Aes256) {
						Console.WriteLine("{0} failed - negotiated cipher was not AES256", testName);
						Shutdown(false);
						return;
					}

					// Do the server read, and write of the messages
					if (DoServerReadWrite()) {
						Shutdown(true);
					}
					else {
						Shutdown(false);
					}
				}
				catch (Exception) {
					Shutdown(false);
				}
			}
			#endregion

			#region AdvancedServerTest
			public void AdvancedServerTest() {
				serverRemoteCertificateValidationCallback = new RemoteCertificateValidationHandler(ValidateRemoteCert);

				try {
					testName = "AdvancedServerTest";
					AcceptConnection(); // sets the client member
					sslStream = new SslStream(client.GetStream(), false, serverRemoteCertificateValidationCallback);
					sslStream.AuthenticateAsServer(testServer.serverCertificate, true, testServer.serverCAChain, SslProtocols.Tls, SslStrength.All, true);

					// Verify mutual authentication
					if (!sslStream.IsMutuallyAuthenticated) {
						Console.WriteLine("{0} failed - stream is not mutually authenticated", testName);
						Shutdown(false);
						return;
					}

					// Verify protocol
					if (sslStream.SslProtocol != SslProtocols.Tls) {
						Console.WriteLine("{0} failed - negotiated non Tls connection", testName);
						Shutdown(false);
						return;
					}
					// Verify cipher strength
					if (sslStream.CipherStrength < 256) {
						Console.WriteLine("{0} failed - negotiated less than 256bit cipher", testName);
						Shutdown(false);
						return;
					}
					// Do the server read, and write of the messages
					if (DoServerReadWrite()) {
						Shutdown(true);
					}
					else {
						Shutdown(false);
					}
				}
				catch (Exception) {
					Shutdown(false);
				}
			}
			#endregion //AdvancedServerTest

			protected void AcceptConnection() {
				listener = new TcpListener(IPAddress.Any, 9000);
				listener.Start(5);
				client = listener.AcceptTcpClient();
			}

			protected bool DoServerReadWrite() {
				bool ret = true;

				// Read the client message
				sslStream.Read(serverReadBuffer, 0, serverReadBuffer.Length);
				if (String.Compare(serverReadBuffer.ToString(), clientMessage.ToString()) != 0) {
					Console.WriteLine("BasicServerTest Read Failure:\nExpected:{0}\nGot:{1}", clientMessage.ToString(), serverReadBuffer.ToString());
					ret = false;
				}
				// Write the server message
				sslStream.Write(serverMessage, 0, serverMessage.Length);

				return ret;
			}

			protected void Shutdown(bool passed) {
				if (sslStream != null) {
					sslStream.Close();
				}
				if (client != null) {
					client.Close();
				}
				if (listener != null) {
					listener.Stop();
				}
				if (passed) {
					Console.WriteLine("{0} - passed", testName);
				}
				else {
					Console.WriteLine("{0} - failed", testName);
				}
			}

			public void BasicClientTest() {
				try {
					testName = "BasicClientTest";
					client = new TcpClient("localhost", 9000);
					sslStream = new SslStream(client.GetStream(), false);
					sslStream.AuthenticateAsClient("localhost");
					if (DoClientReadWrite()) {
						Shutdown(true);
					}
					else {
						Shutdown(false);
					}
				}
				catch (Exception) {
					Shutdown(false);
				}
			}

			#region IntermediateClientTest
			public void IntermediateClientTest() {
				try {
					testName = "IntermediateClientTest";
					client = new TcpClient("localhost", 9000);
					sslStream = new SslStream(client.GetStream(), false);
					sslStream.AuthenticateAsClient("localhost", null, null, SslProtocols.Tls, SslStrength.Medium | SslStrength.High, false);
					if (sslStream.SslProtocol != SslProtocols.Tls) {
						Console.WriteLine("{0} failed - negotiated a non Tls connection", testName);
						Shutdown(false);
						return;
					}
					if (sslStream.CipherStrength < 256) {
						Console.WriteLine("{0} failed - negotiated less that 256bit cipher", testName);
						Console.WriteLine("Cipher={0}\nCipherStrength = {1}", sslStream.CipherAlgorithm.ToString(), sslStream.CipherStrength);
						Shutdown(false);
						return;
					}
					if (sslStream.CipherAlgorithm != CipherAlgorithmType.Aes256) {
						Console.WriteLine("{0} failed - negotiatied cipher wasn't Aes256", testName);
						Console.WriteLine("Cipher was {0}, expected {0}", sslStream.CipherAlgorithm.ToString(), CipherAlgorithmType.Aes256.ToString());
						Shutdown(false);
						return;
					}
					if (DoClientReadWrite()) {
						Shutdown(true);
					}
					else {
						Shutdown(false);
					}
				}
				catch (Exception ex) {
					Shutdown(false);
					Console.WriteLine(ex);
				}
			}
			#endregion  //IntermediateClientTest

			#region AdvancedClientTest

			protected X509Certificate clientCertificateSelectionCallback(object sender, string targetHost, X509List localCerts, X509Certificate remoteCert, string[] acceptableIssuers) {
				X509Certificate retCert = null;

				// check target host?

				for (int i = 0; i < acceptableIssuers.GetLength(0); i++) {
					X509Name name = new X509Name(acceptableIssuers[i]);

					foreach (X509Certificate cert in localCerts) {
						if (cert.Issuer.CompareTo(name) == 0) {
							retCert = cert;
							break;
						}
						cert.Dispose();
					}
					name.Dispose();
				}
				return retCert;
			}

			bool CheckCert(X509Certificate cert, X509Chain chain) {
				if (cert == null || chain == null) {
					return false;
				}

				foreach (X509Certificate certificate in chain) {
					if (cert == certificate) {
						return true;
					}
				}

				return false;
			}

			bool ValidateRemoteCert(object obj, X509Certificate cert, X509Chain chain, int depth, VerifyResult result) {
				bool ret = false;

				switch (result) {
					case VerifyResult.X509_V_ERR_CERT_UNTRUSTED:
					case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
					case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
					case VerifyResult.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: {
							// Check the chain to see if there is a match for the cert
							ret = CheckCert(cert, chain);
							if (!ret && depth != 0) {
								ret = true;  // We want to keep checking until we get to depth 0
							}
						}
						break;
					case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
					case VerifyResult.X509_V_ERR_CERT_NOT_YET_VALID: {
							Console.WriteLine("Certificate is not valid yet");
							ret = false;
						}
						break;
					case VerifyResult.X509_V_ERR_CERT_HAS_EXPIRED:
					case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: {
							Console.WriteLine("Certificate is expired");
							ret = false;
						}
						break;
					case VerifyResult.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: {
							// we received a self signed cert - check to see if it's in our store
							ret = CheckCert(cert, chain);
						}
						break;
					case VerifyResult.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: {
							// A self signed certificate was encountered in the chain
							// Check the chain to see if there is a match for the cert
							ret = CheckCert(cert, chain);
							if (!ret && depth != 0) {
								ret = true;  // We want to keep checking until we get to depth 0
							}
						}
						break;
					case VerifyResult.X509_V_OK: {
							ret = true;
						}
						break;
				}
				return ret;
			}

			public void AdvancedClientTest() {
				//Initialize delegates for certificate callbacks
				clientRemoteCertificateValidationCallback = new RemoteCertificateValidationHandler(ValidateRemoteCert);
				clientLocalCertificateSelectionCallback = new LocalCertificateSelectionHandler(clientCertificateSelectionCallback);

				try {
					testName = "AdvancedClientTest";
					client = new TcpClient("localhost", 9000);
					// Create the SslStream object with the certificate callbacks
					sslStream = new SslStream(client.GetStream(), false, clientRemoteCertificateValidationCallback, clientLocalCertificateSelectionCallback);
					// Initialize with client certificate list, and client CA chain
					sslStream.AuthenticateAsClient("localhost", testServer.clientCertificateList, testServer.clientCAChain, SslProtocols.Tls, SslStrength.Medium | SslStrength.High, true);

					// Verify mutual authentication
					if (!sslStream.IsMutuallyAuthenticated) {
						Console.WriteLine("{0} failed - Stream is not mutally authenticated", testName);
						Shutdown(false);
					}
					// Verify protocol
					if (sslStream.SslProtocol != SslProtocols.Tls) {
						Console.WriteLine("{0} failed - negotiated a non Tls connection", testName);
						Shutdown(false);
					}
					// Verify cipher strength
					if (sslStream.CipherStrength < 256) {
						Console.WriteLine("{0} failed - negotiated less that 256bit cipher", testName);
						Console.WriteLine("Cipher={0}\nCipherStrength = {1}", sslStream.CipherAlgorithm.ToString(), sslStream.CipherStrength);
						Shutdown(false);
					}
					// Verify cipher
					if (sslStream.CipherAlgorithm != CipherAlgorithmType.Aes256) {
						Console.WriteLine("{0} failed - negotiatied cipher wasn't Aes256", testName);
						Console.WriteLine("Cipher was {0}, expected {0}", sslStream.CipherAlgorithm.ToString(), CipherAlgorithmType.Aes256.ToString());
						Shutdown(false);
					}
					if (DoClientReadWrite()) {
						Shutdown(true);
					}
					else {
						Shutdown(false);
					}
				}
				catch (Exception ex) {
					Shutdown(false);
					Console.WriteLine(ex);
				}
			}
			#endregion // AdvancedClientTest

			protected bool DoClientReadWrite() {
				bool ret = true;

				// Write the client message
				sslStream.Write(clientMessage, 0, clientMessage.Length);
				// Read the server message
				sslStream.Read(clientReadBuffer, 0, clientReadBuffer.Length);
				if (String.Compare(clientReadBuffer.ToString(), serverMessage.ToString()) != 0) {
					Console.WriteLine("BasicServerTest Read Failure:\nExpected:{0}\nGot:{1}", serverMessage.ToString(), clientReadBuffer.ToString());
					ret = false;
				}
				sslStream.Close();
				client.Close();

				return ret;
			}

			#endregion  //BasicSyncServerTest

		}

		public class AsyncServerTests
		{
			public TestServer testServer = null;
			public byte[] clientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
			public byte[] serverMessage = Encoding.ASCII.GetBytes("This is a message from the server");
			byte[] serverReadBuffer = new byte[256];
			byte[] clientReadBuffer = new byte[256];
			TcpListener listener = null;
			TcpClient client = null;
			SslStream sslStream = null;
			ManualResetEvent testComplete = new ManualResetEvent(false);
			string testName = "Not set";
			protected RemoteCertificateValidationHandler clientRemoteCertificateValidationCallback = null;
			protected LocalCertificateSelectionHandler clientLocalCertificateSelectionCallback = null;
			protected RemoteCertificateValidationHandler serverRemoteCertificateValidationCallback = null;

			public AsyncServerTests(TestServer testServer) {
				this.testServer = testServer;
				// Initialize certificate callbacks (only used for Advanced test)
				clientRemoteCertificateValidationCallback = new RemoteCertificateValidationHandler(ValidateRemoteCert);
				clientLocalCertificateSelectionCallback = new LocalCertificateSelectionHandler(clientCertificateSelectionCallback);
				serverRemoteCertificateValidationCallback = new RemoteCertificateValidationHandler(ValidateRemoteCert);
			}

			public void Shutdown(bool passed) {
				if (listener != null) {
					listener.Stop();
					listener = null;
				}
				if (sslStream != null) {
					sslStream.Close();
					sslStream = null;
				}
				if (client != null) {
					client.Close();
					client = null;
				}
				if (passed) {
					Console.WriteLine("{0} - passed", testName);
				}
				else {
					System.Diagnostics.StackTrace stack = new System.Diagnostics.StackTrace();
					Console.WriteLine("{0} - failed - method={1}", testName, stack.GetFrame(1).ToString());
				}
				// Signal the event to end the test
				testComplete.Set();
			}

			protected X509Certificate clientCertificateSelectionCallback(object sender, string targetHost, X509List localCerts, X509Certificate remoteCert, string[] acceptableIssuers) {
				X509Certificate retCert = null;

				// check target host?

				for (int i = 0; i < acceptableIssuers.GetLength(0); i++) {
					X509Name name = new X509Name(acceptableIssuers[i]);

					foreach (X509Certificate cert in localCerts) {
						if (cert.Issuer.CompareTo(name) == 0) {
							retCert = cert;
							break;
						}
						cert.Dispose();
					}
					name.Dispose();
				}
				return retCert;
			}

			bool CheckCert(X509Certificate cert, X509Chain chain) {
				if (cert == null || chain == null) {
					return false;
				}

				foreach (X509Certificate certificate in chain) {
					if (cert == certificate) {
						return true;
					}
				}

				return false;
			}

			bool ValidateRemoteCert(object obj, X509Certificate cert, X509Chain chain, int depth, VerifyResult result) {
				bool ret = false;

				switch (result) {
					case VerifyResult.X509_V_ERR_CERT_UNTRUSTED:
					case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
					case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
					case VerifyResult.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: {
							// Check the chain to see if there is a match for the cert
							ret = CheckCert(cert, chain);
							if (!ret && depth != 0) {
								ret = true;  // We want to keep checking until we get to depth 0
							}
						}
						break;
					case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
					case VerifyResult.X509_V_ERR_CERT_NOT_YET_VALID: {
							Console.WriteLine("Certificate is not valid yet");
							ret = false;
						}
						break;
					case VerifyResult.X509_V_ERR_CERT_HAS_EXPIRED:
					case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: {
							Console.WriteLine("Certificate is expired");
							ret = false;
						}
						break;
					case VerifyResult.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: {
							// we received a self signed cert - check to see if it's in our store
							ret = CheckCert(cert, chain);
						}
						break;
					case VerifyResult.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: {
							// A self signed certificate was encountered in the chain
							// Check the chain to see if there is a match for the cert
							ret = CheckCert(cert, chain);
							if (!ret && depth != 0) {
								ret = true;  // We want to keep checking until we get to depth 0
							}
						}
						break;
					case VerifyResult.X509_V_OK: {
							ret = true;
						}
						break;
				}
				return ret;
			}

			#region BasicAsyncServerTest
			public void BasicAsyncServerTest() {
				testName = "BasicAsyncServerTest";
				testComplete.Reset();
				listener = new TcpListener(IPAddress.Any, 9000);
				listener.Start(5);
				listener.BeginAcceptTcpClient(new AsyncCallback(OnAsyncServerAccept), null);
				testComplete.WaitOne();
			}

			public void IntermediateAsyncServerTest() {
				testName = "IntermediateAsyncServerTest";
				testComplete.Reset();
				listener = new TcpListener(IPAddress.Any, 9000);
				listener.Start(5);
				listener.BeginAcceptTcpClient(new AsyncCallback(OnAsyncServerAccept), null);
				testComplete.WaitOne();
			}

			public void AdvancedAsyncServerTest() {
				testName = "AdvancedAsyncServerTest";
				testComplete.Reset();
				listener = new TcpListener(IPAddress.Any, 9000);
				listener.Start(5);
				listener.BeginAcceptTcpClient(new AsyncCallback(OnAsyncServerAccept), null);
				testComplete.WaitOne();
			}

			protected void OnAsyncServerAccept(IAsyncResult ar) {
				client = listener.EndAcceptTcpClient(ar);
				if (testName == "BasicAsyncServerTest") {
					sslStream = new SslStream(client.GetStream(), false);
					sslStream.BeginAuthenticateAsServer(testServer.serverCertificate, new AsyncCallback(OnAsyncAuthenticateAsServer), null);
				}
				else if (testName == "IntermediateAsyncServerTest") {
					sslStream = new SslStream(client.GetStream(), false);
					sslStream.BeginAuthenticateAsServer(testServer.serverCertificate, false, null, SslProtocols.Tls, SslStrength.All, false, new AsyncCallback(OnAsyncAuthenticateAsServer), null);
				}
				else if (testName == "AdvancedAsyncServerTest") {
					sslStream = new SslStream(client.GetStream(), false, serverRemoteCertificateValidationCallback);
					sslStream.BeginAuthenticateAsServer(testServer.serverCertificate, true, testServer.serverCAChain, SslProtocols.Tls, SslStrength.All, true, new AsyncCallback(OnAsyncAuthenticateAsServer), null);
				}
			}

			protected void OnAsyncAuthenticateAsServer(IAsyncResult ar) {
				try {
					sslStream.EndAuthenticateAsServer(ar);
					if (testName == "IntermediateAsyncServerTest" || testName == "AdvancedAsyncServerTest") {
						// Verify protocol
						if (sslStream.SslProtocol != SslProtocols.Tls) {
							Console.WriteLine("{0} failed - negotiated non Tls connection", testName);
							Shutdown(false);
							return;
						}
						// Verify cipher strength
						if (sslStream.CipherStrength < 256) {
							Console.WriteLine("{0} failed - negotiated less than 256bit cipher", testName);
							Shutdown(false);
							return;
						}
						//Verify cipher
						if (sslStream.CipherAlgorithm != CipherAlgorithmType.Aes256) {
							Console.WriteLine("{0} failed - negotiated cipher was not AES256", testName);
							Shutdown(false);
							return;
						}
					}
					if (testName == "AdvancedAsyncServerTest") {
						if (!sslStream.IsMutuallyAuthenticated) {
							Console.WriteLine("{0} failed - stream is not mutually authenticated", testName);
							Shutdown(false);
							return;
						}
					}
				}
				catch (Exception) {
					Shutdown(false);
				}
				sslStream.BeginRead(serverReadBuffer, 0, serverReadBuffer.Length, new AsyncCallback(OnAsyncServerRead), null);
			}

			protected void OnAsyncServerRead(IAsyncResult ar) {
				int bytesRead = sslStream.EndRead(ar);
				if (bytesRead <= 0) {
					Shutdown(false);
				}
				if (String.Compare(serverReadBuffer.ToString(), clientMessage.ToString()) != 0) {
					Console.WriteLine("{0} Read Failure:\nExpected:{0}\nGot:{1}", testName, clientMessage.ToString(), serverReadBuffer.ToString());
					Shutdown(false);
				}
				sslStream.BeginWrite(serverMessage, 0, serverMessage.Length, new AsyncCallback(OnAsyncServerWrite), null);
			}

			void OnAsyncServerWrite(IAsyncResult ar) {
				try {
					sslStream.EndWrite(ar);
					// And we're done...  cleanup
					Shutdown(true);
				}
				catch (Exception) {
					Shutdown(false);
				}
			}

			#endregion // BasicAsyncServerTest

			#region // BasicAsyncClientTest

			public void BasicAsyncClientTest() {
				testName = "BasicAsyncClientTest";
				client = new TcpClient(AddressFamily.InterNetwork);
				client.BeginConnect("localhost", 9000, new AsyncCallback(OnAsyncClientConnect), null);
				testComplete.WaitOne();
			}

			public void IntermediateAsyncClientTest() {
				testName = "IntermediateAsyncClientTest";
				client = new TcpClient(AddressFamily.InterNetwork);
				client.BeginConnect("localhost", 9000, new AsyncCallback(OnAsyncClientConnect), null);
				testComplete.WaitOne();
			}

			public void AdvancedAsyncClientTest() {
				testName = "AdvancedAsyncClientTest";
				client = new TcpClient(AddressFamily.InterNetwork);
				client.BeginConnect("localhost", 9000, new AsyncCallback(OnAsyncClientConnect), null);
				testComplete.WaitOne();
			}

			public void OnAsyncClientConnect(IAsyncResult ar) {
				try {
					client.EndConnect(ar);
				}
				catch (Exception) {
					Shutdown(false);
				}
				if (testName == "BasicAsyncClientTest") {
					sslStream = new SslStream(client.GetStream(), false);
					sslStream.BeginAuthenticateAsClient("localhost", new AsyncCallback(OnAsyncAuthenticateAsClient), null);
				}
				else if (testName == "IntermediateAsyncClientTest") {
					sslStream = new SslStream(client.GetStream(), false);
					sslStream.BeginAuthenticateAsClient("localhost", null, null, SslProtocols.Tls, SslStrength.Medium | SslStrength.High, false, new AsyncCallback(OnAsyncAuthenticateAsClient), null);
				}
				else if (testName == "AdvancedAsyncClientTest") {
					sslStream = new SslStream(client.GetStream(), false, clientRemoteCertificateValidationCallback, clientLocalCertificateSelectionCallback);
					sslStream.BeginAuthenticateAsClient("localhost", testServer.clientCertificateList, testServer.clientCAChain, SslProtocols.Tls, SslStrength.Medium | SslStrength.High, true, new AsyncCallback(OnAsyncAuthenticateAsClient), null);
				}
			}

			public void OnAsyncAuthenticateAsClient(IAsyncResult ar) {
				try {
					sslStream.EndAuthenticateAsClient(ar);
					if (testName == "IntermediateAsyncClientTest" || testName == "AdvancedAsyncClientTest") {
						if (sslStream.SslProtocol != SslProtocols.Tls) {
							Console.WriteLine("{0} failed - negotiated a non Tls connection", testName);
							Shutdown(false);
							return;
						}
						if (sslStream.CipherStrength < 256) {
							Console.WriteLine("{0} failed - negotiated less that 256bit cipher", testName);
							Console.WriteLine("Cipher={0}\nCipherStrength = {1}", sslStream.CipherAlgorithm.ToString(), sslStream.CipherStrength);
							Shutdown(false);
							return;
						}
						if (sslStream.CipherAlgorithm != CipherAlgorithmType.Aes256) {
							Console.WriteLine("{0} failed - negotiatied cipher wasn't Aes256", testName);
							Console.WriteLine("Cipher was {0}, expected {0}", sslStream.CipherAlgorithm.ToString(), CipherAlgorithmType.Aes256.ToString());
							Shutdown(false);
							return;
						}
					}
					if (testName == "AdvancedAsyncClientTest") {
						// Verify mutual authentication
						if (!sslStream.IsMutuallyAuthenticated) {
							Console.WriteLine("{0} failed - Stream is not mutally authenticated", testName);
							Shutdown(false);
							return;
						}
					}
				}
				catch (Exception) {
					Shutdown(false);
				}
				sslStream.BeginWrite(clientMessage, 0, clientMessage.Length, new AsyncCallback(OnAsyncClientWrite), null);
			}

			public void OnAsyncClientWrite(IAsyncResult ar) {
				try {
					sslStream.EndWrite(ar);
				}
				catch (Exception) {
					Shutdown(false);
				}
				sslStream.BeginRead(clientReadBuffer, 0, clientReadBuffer.Length, new AsyncCallback(OnAsyncClientRead), null);
			}

			public void OnAsyncClientRead(IAsyncResult ar) {
				int bytesRead = 0;

				try {
					bytesRead = sslStream.EndRead(ar);
				}
				catch (Exception) {
					Shutdown(false);
				}
				if (bytesRead <= 0) {
					Shutdown(false);
				}
				if (String.Compare(clientReadBuffer.ToString(), serverMessage.ToString()) != 0) {
					Console.WriteLine("BasicAsyncClientTest Read Failure:\nExpected:{0}\nGot:{1}", serverMessage.ToString(), clientReadBuffer.ToString());
					Shutdown(false);
				}
				else {
					Shutdown(true);
				}
			}

			#endregion // BasicAsyncClientTest
		}

		public void ServerTestThreadProc() {
			// Run synchronous tests
			SyncServerTests tests = new SyncServerTests(this);
			tests.BasicServerTest();
			tests.IntermediateServerTest();
			tests.AdvancedServerTest();

			// Run asynchronous tests
			AsyncServerTests asyncTests = new AsyncServerTests(this);
			asyncTests.BasicAsyncServerTest();
			asyncTests.IntermediateAsyncServerTest();
			asyncTests.AdvancedAsyncServerTest();
		}

		public void ClientTestThreadProc() {
			Thread.Sleep(500);  // Ensure that the server is ready!
			// Run synchronous tests
			SyncServerTests tests = new SyncServerTests(this);
			tests.BasicClientTest();
			Thread.Sleep(200);
			tests.IntermediateClientTest();
			Thread.Sleep(200);
			tests.AdvancedClientTest();

			// Run asynchronous tests
			AsyncServerTests asyncTests = new AsyncServerTests(this);
			asyncTests.BasicAsyncClientTest();
			Thread.Sleep(200);
			asyncTests.IntermediateAsyncClientTest();
			Thread.Sleep(200);
			asyncTests.AdvancedAsyncClientTest();

		}
		
		[Test]
		[Ignore]
		public void TestCase() {
			string serverCertPath = @"../../test/certs/server.pfx";
			string serverPrivateKeyPassword = "p@ssw0rd";
			string caFilePath = "../../test/certs/ca_chain.pem";
			string clientCertPath = "../../test/certs/client.pfx";
			string clientPrivateKeyPassword = "p@ssw0rd";

			// Initialize OpenSSL for multithreaded use
			ThreadInitialization.InitializeThreads();
			try {
				// Intitialize server certificates
				serverCAChain = LoadCACertificateChain(caFilePath);
				serverCertificate = LoadPKCS12Certificate(serverCertPath, serverPrivateKeyPassword);

				// Kick the server thread
				Thread serverThread = new Thread(new ThreadStart(ServerTestThreadProc));
				serverThread.Start();

				// Intialize the client certificates
				clientCAChain = LoadCACertificateChain(caFilePath);
				X509Certificate clientCert = LoadPKCS12Certificate(clientCertPath, clientPrivateKeyPassword);
				// Add the cert to the client certificate list
				clientCertificateList = new X509List();
				clientCertificateList.Add(clientCert);

				// Kick the client thread
				Thread clientThread = new Thread(new ThreadStart(ClientTestThreadProc));
				clientThread.Start();

				// Wait for the threads to exit
				serverThread.Join();
				clientThread.Join();

				// Cleanup
				serverCertificate.Dispose();
				serverCAChain.Dispose();
				clientCAChain.Dispose();
				clientCert.Dispose();
			}
			catch (Exception ex) {
				Console.WriteLine("Server test failed with exception: {0}", ex.Message);
			}
			ThreadInitialization.UninitializeThreads();
		}
	}
}
