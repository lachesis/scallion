// Copyright (c) 2009-2012 Frank Laub
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
using System.IO;
using System.Text;
using NUnit.Framework;
using OpenSSL;
using OpenSSL.Core;
using OpenSSL.Crypto;
using OpenSSL.X509;

namespace UnitTests
{
	[TestFixture]
	public class SourceForgeBugs : TestBase
	{
		/// <summary>
		/// BIO.ReadBytes() throws error when count = 0
		/// </summary>
		[Test]
		public void Bug2993305()
		{
			BIO mb = BIO.MemoryBuffer();
			mb.Write("Some junk");
			ArraySegment<byte> result = mb.ReadBytes(0);
			Assert.AreEqual(0, result.Count);
		}
		
		/// <summary>
		/// WritePrivateKey fails with null Cipher type
		/// </summary>
		[Test]
		[ExpectedException(typeof(OpenSslException))]
		public void Bug3017248()
		{
			CryptoKey key = new CryptoKey(new DSA(true));
			BIO output = BIO.MemoryBuffer();
			key.WritePrivateKey(output, Cipher.Null, "password");
			output.SetClose(BIO.CloseOption.Close);
			Console.WriteLine(output.ReadString());
		}

		/// <summary>
		/// OpenSSL.X509.FileSerialNumber malfunctions
		/// Check for invalid directory
		/// </summary>
		[Test]
		[ExpectedException(typeof(DirectoryNotFoundException))]
		public void Bug3018093_1()
		{
			FileSerialNumber fsn = new FileSerialNumber("/does/not/exist");
			int serial = fsn.Next();
		}

		/// <summary>
		/// OpenSSL.X509.FileSerialNumber malfunctions
		/// Check that non-existant file is created and subsequently valid
		/// </summary>
		[Test]
		public void Bug3018093_2()
		{
			string tmp = Path.GetTempPath();
			string path = Path.Combine(tmp, "new_serial");
			Console.WriteLine(path);

			File.Delete(path);
			FileSerialNumber fsn1 = new FileSerialNumber(path);
			Assert.AreEqual(1, fsn1.Next());
			Assert.AreEqual(2, fsn1.Next());

			File.Delete(path);
			FileSerialNumber fsn2 = new FileSerialNumber(path);
			Assert.AreEqual(1, fsn2.Next());
			Assert.AreEqual(2, fsn2.Next());
		}
		
		[Test]
		/// <summary>
		/// Exception in encrypting less than 8 bytes with Blowfish_CBC
		/// </summary>
		public void Bug3066497()
		{
			CipherContext cc = new CipherContext(Cipher.Blowfish_CBC);
			byte[] inputData = Encoding.UTF8.GetBytes("1234567");
			byte[] key = Encoding.UTF8.GetBytes("secret!!");
			byte[] iv = Encoding.UTF8.GetBytes("secret!!");
			byte[] outputData = cc.Encrypt(inputData, key, iv);
		}
	}
}

