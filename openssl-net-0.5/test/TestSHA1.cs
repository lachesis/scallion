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
	public class TestSHA1 : TestBase
	{
		readonly string[] tests = {
			"abc",
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		};

		readonly string[] results = {
			"A9-99-3E-36-47-06-81-6A-BA-3E-25-71-78-50-C2-6C-9C-D0-D8-9D",
			"84-98-3E-44-1C-3B-D2-6E-BA-AE-4A-A1-F9-51-29-E5-E5-46-70-F1",
		};

		const string bigret = "34-AA-97-3C-D4-C4-DA-A4-F6-1E-EB-2B-DB-AD-27-31-65-34-01-6F";
		
		[Test]
		public void TestCase()
		{
			using (MessageDigestContext ctx = new MessageDigestContext(MessageDigest.SHA1)) {
				for (int i = 0; i < tests.Length; i++) {
					byte[] msg = Encoding.ASCII.GetBytes(this.tests[i]);
					byte[] ret = ctx.Digest(msg);

					string str = BitConverter.ToString(ret);
					Assert.AreEqual(results[i], str);
				}

				byte[] buf = Encoding.ASCII.GetBytes(new string('a', 1000));
				ctx.Init();
				for (int i = 0; i < 1000; i++) {
					ctx.Update(buf);
				}

				byte[] retx = ctx.DigestFinal();
				string strx = BitConverter.ToString(retx);
				Assert.AreEqual(bigret, strx);
			}
		}
	}
}
