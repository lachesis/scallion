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
using System.Collections.Generic;
using System.Text;
using OpenSSL;
using OpenSSL.Crypto;
using NUnit.Framework;

namespace UnitTests
{
	[TestFixture]
	public class TestSHA256 : TestBase
	{
		byte[][] app = {
			new byte[] {
				0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
				0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
				0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
				0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad	
			},
			new byte[] {
				0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,
				0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
				0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,
				0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1	
			},
			new byte[] {
				0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,
				0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
				0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,
				0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0	
			},
		};

		byte[][] addenum = {
			new byte[] {
				0x23,0x09,0x7d,0x22,0x34,0x05,0xd8,0x22,
				0x86,0x42,0xa4,0x77,0xbd,0xa2,0x55,0xb3,
				0x2a,0xad,0xbc,0xe4,0xbd,0xa0,0xb3,0xf7,
				0xe3,0x6c,0x9d,0xa7 
			},
			new byte[] {
				0x75,0x38,0x8b,0x16,0x51,0x27,0x76,0xcc,
				0x5d,0xba,0x5d,0xa1,0xfd,0x89,0x01,0x50,
				0xb0,0xc6,0x45,0x5c,0xb4,0xf5,0x8b,0x19,
				0x52,0x52,0x25,0x25 
			},
			new byte[] {
				0x20,0x79,0x46,0x55,0x98,0x0c,0x91,0xd8,
				0xbb,0xb4,0xc1,0xea,0x97,0x61,0x8a,0x4b,
				0xf0,0x3f,0x42,0x58,0x19,0x48,0xb2,0xee,
				0x4e,0xe7,0xad,0x67 
			},
		};
		
		[Test]
		public void TestCase()
		{
			using (MessageDigestContext ctx = new MessageDigestContext(MessageDigest.SHA256))
				this.GenericTest("SHA-256", ctx, this.app);

			using (MessageDigestContext ctx = new MessageDigestContext(MessageDigest.SHA224))
				this.GenericTest("SHA-224", ctx, this.addenum);
		}

		private void GenericTest(string name, MessageDigestContext ctx, byte[][] results)
		{
			Console.WriteLine("Testing {0}", name);

			byte[] digest = ctx.Digest(Encoding.ASCII.GetBytes("abc"));
			string str1 = BitConverter.ToString(digest);
			string str2 = BitConverter.ToString(results[0]);
			Assert.AreEqual(str2, str1);

			Console.Write(".");

			byte[] msg = Encoding.ASCII.GetBytes(
				"abcdbcde" + "cdefdefg" + "efghfghi" +
				"ghijhijk" + "ijkljklm" + "klmnlmno" + "mnopnopq");
			digest = ctx.Digest(msg);
			str1 = BitConverter.ToString(digest);
			str2 = BitConverter.ToString(results[1]);
			Assert.AreEqual(str2, str1);

			Console.Write(".");

			ctx.Init();
			for (int i = 0; i < 1000000; i += 160)
			{
				msg = Encoding.ASCII.GetBytes(
					"aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" +
					"aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" +
					"aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" +
					"aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" +
					"aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa");
				int len = (1000000 - i) < 160 ? 1000000 - i : 160;
				byte[] tmp = new byte[len];
				Buffer.BlockCopy(msg, 0, tmp, 0, len);
				ctx.Update(tmp);
			}
			digest = ctx.DigestFinal();

			str1 = BitConverter.ToString(digest);
			str2 = BitConverter.ToString(results[2]);
			Assert.AreEqual(str2, str1);

			Console.Write(".");

			Console.WriteLine(" passed.");
		}
	}
}
