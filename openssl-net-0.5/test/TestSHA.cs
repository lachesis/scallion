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
	public class TestSHA : TestBase
	{
		readonly string[] tests = {
			"abc",
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		};

		readonly string[] results = {
			"01-64-B8-A9-14-CD-2A-5E-74-C4-F7-FF-08-2C-4D-97-F1-ED-F8-80",
			"D2-51-6E-E1-AC-FA-5B-AF-33-DF-C1-C4-71-E4-38-44-9E-F1-34-C8",
		};

		const string bigret = "32-32-AF-FA-48-62-8A-26-65-3B-5A-AA-44-54-1F-D9-0D-69-06-03";

		[Test]
		public void TestCase()
		{
			using (MessageDigestContext ctx = new MessageDigestContext(MessageDigest.SHA)) {
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
