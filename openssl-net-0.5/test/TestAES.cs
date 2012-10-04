// Copyright (c) 2006-2007 Frank Laub
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
using NUnit.Framework;
using OpenSSL.Crypto;
using System.Text;

namespace UnitTests
{
	[TestFixture]
	public class TestAES : TestBase
	{
		[Test]
		public void TestCase()
		{
			string magic = "Salted__";
			const int PKCS5_SALT_LEN = 8;
			string base64 = "U2FsdGVkX1/moDHvAjok9X4prr8TXQtv9LRAIHk1IE8=";
			byte[] input = Convert.FromBase64String(base64);
			byte[] salt = new byte[PKCS5_SALT_LEN];
			byte[] msg = new byte[input.Length - magic.Length - PKCS5_SALT_LEN];
			Buffer.BlockCopy(input, magic.Length, salt, 0, salt.Length);
			Buffer.BlockCopy(input, magic.Length + PKCS5_SALT_LEN, msg, 0, msg.Length);

			using (CipherContext cc = new CipherContext(Cipher.AES_256_CBC)) {
				byte[] iv;
				byte[] password = Encoding.ASCII.GetBytes("example");
				byte[] key = cc.BytesToKey(MessageDigest.MD5, salt, password, 1, out iv);
				byte[] output = cc.Decrypt(msg, key, iv);
				string text = Encoding.ASCII.GetString(output);
				Console.WriteLine(text);
			}
		}
	}
}

