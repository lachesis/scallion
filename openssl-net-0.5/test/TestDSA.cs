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
using System.IO;
using OpenSSL.Core;
using System.Text;

namespace UnitTests
{
	[TestFixture]
	public class TestDSA : TestBase
	{
		const string rnd_seed = "string to make the random number generator think it has entropy";
		const string str1 = "12345678901234567890";

		readonly byte[] seed = { 
			0xd5,0x01,0x4e,0x4b,0x60,0xef,0x2b,0xa8,0xb6,0x21,0x1b,0x40,
			0x62,0xba,0x32,0x24,0xe0,0x42,0x7d,0xd3,
		};

		readonly byte[] out_p = {
			0x8d,0xf2,0xa4,0x94,0x49,0x22,0x76,0xaa,
			0x3d,0x25,0x75,0x9b,0xb0,0x68,0x69,0xcb,
			0xea,0xc0,0xd8,0x3a,0xfb,0x8d,0x0c,0xf7,
			0xcb,0xb8,0x32,0x4f,0x0d,0x78,0x82,0xe5,
			0xd0,0x76,0x2f,0xc5,0xb7,0x21,0x0e,0xaf,
			0xc2,0xe9,0xad,0xac,0x32,0xab,0x7a,0xac,
			0x49,0x69,0x3d,0xfb,0xf8,0x37,0x24,0xc2,
			0xec,0x07,0x36,0xee,0x31,0xc8,0x02,0x91,
		};

		readonly byte[] out_q = {
			0xc7,0x73,0x21,0x8c,0x73,0x7e,0xc8,0xee,
			0x99,0x3b,0x4f,0x2d,0xed,0x30,0xf4,0x8e,
			0xda,0xce,0x91,0x5f,
		};

		readonly byte[] out_g = {
			0x62,0x6d,0x02,0x78,0x39,0xea,0x0a,0x13,
			0x41,0x31,0x63,0xa5,0x5b,0x4c,0xb5,0x00,
			0x29,0x9d,0x55,0x22,0x95,0x6c,0xef,0xcb,
			0x3b,0xff,0x10,0xf3,0x99,0xce,0x2c,0x2e,
			0x71,0xcb,0x9d,0xe5,0xfa,0x24,0xba,0xbf,
			0x58,0xe5,0xb7,0x95,0x21,0x92,0x5c,0x9c,
			0xc4,0x2e,0x9f,0x6f,0x46,0x4b,0x08,0x8c,
			0xc5,0x72,0xaf,0x53,0xe6,0xd7,0x88,0x02,
		};

		private void DoTest(DSA dsa)
		{
			Console.WriteLine("seed");
			Console.WriteLine(BitConverter.ToString(seed));
			Console.WriteLine("counter={0} h={1}", dsa.Counter, dsa.H);

			Console.WriteLine(dsa);
			
			Assert.AreEqual(105, dsa.Counter);
			Assert.AreEqual(2, dsa.H.ToInt32());

			using (BigNumber q = BigNumber.FromArray(this.out_q)) {
				Assert.IsTrue(q == dsa.Q);
			}

			using (BigNumber p = BigNumber.FromArray(this.out_p)) {
				Assert.IsTrue(p == dsa.P);
			}

			using (BigNumber g = BigNumber.FromArray(this.out_g)) {
				Assert.IsTrue(g == dsa.G);
			}

			byte[] msg = Encoding.ASCII.GetBytes(str1);

			dsa.ConstantTime = true;
			dsa.GenerateKeys();

			byte[] sig = dsa.Sign(msg);
			Assert.IsTrue(dsa.Verify(msg, sig));

			dsa.ConstantTime = false;
			dsa.GenerateKeys();
			sig = dsa.Sign(msg);
			Assert.IsTrue(dsa.Verify(msg, sig));
		}

		[Test]
		public void TestCase()
		{
			OpenSSL.Core.Random.Seed(rnd_seed);
		
			Console.WriteLine("test generation of DSA parameters");

			using (DSA dsa = new DSA(512, seed, 0, new BigNumber.GeneratorHandler(this.OnStatus), null)) {
				DoTest(dsa);
			}
		}

		private int ok = 0;
		private int num = 0;

		private int OnStatus(int p, int n, object arg)
		{
			TextWriter cout = Console.Out;

			switch (p) {
				case 0: cout.Write('.'); num++; break;
				case 1: cout.Write('+'); break;
				case 2: cout.Write('*'); ok++; break;
				case 3: cout.WriteLine(); break;
			}

			if (ok == 0 && (p == 0) && (num > 1)) {
				Assert.Fail();
				return 0;
			}

			return 1;
		}
	}
}

