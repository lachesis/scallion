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

namespace UnitTests
{
	[TestFixture]
	public class TestRandom : TestBase
	{
		[Test]
		public void TestCase()
		{
			Console.WriteLine("Testing random");
			int err = 0;

			byte[] buf = OpenSSL.Core.Random.PseudoBytes(2500);

			uint n1 = 0;
			uint[] n2 = new uint[16];
			uint[,] runs = new uint[2, 34];

			int sign = 0;
			int nsign = 0;

			for (int i = 0; i < buf.Length; i++) {
				int j = buf[i];

				n2[j & 0x0f]++;
				n2[(j >> 4) & 0x0f]++;

				for (int k = 0; k < 8; k++) {
					int s = (j & 0x01);
					if (s == sign)
						nsign++;
					else {
						if (nsign > 34)
							nsign = 34;
						if (nsign != 0) {
							runs[sign, nsign - 1]++;
							if (nsign > 6)
								runs[sign, 5]++;
						}
						sign = s;
						nsign = 1;
					}

					if (s != 0) n1++;
					j >>= 1;
				}
			}
			if (nsign > 34)
				nsign = 34;
			if (nsign != 0)
				runs[sign, nsign - 1]++;

			#region Test 1
			Assert.IsTrue((9654 < n1) && (n1 < 10346));
			#endregion

			#region Test 2
			uint d = 0;
			for (int i = 0; i < 16; i++)
				d += n2[i] * n2[i];
			d = (d * 8) / 25 - 500000;
			Assert.IsTrue((103 < d) && (d < 5740));
			#endregion

			#region Test 3
			for (int i = 0; i < 2; i++) {
				Assert.IsTrue((2267 < runs[i, 0]) && (runs[i, 0] < 2733));
				Assert.IsTrue((1079 < runs[i, 1]) && (runs[i, 1] < 1421));
				Assert.IsTrue((502 < runs[i, 2]) && (runs[i, 2] < 748));
				Assert.IsTrue((223 < runs[i, 3]) && (runs[i, 3] < 402));
				Assert.IsTrue((90 < runs[i, 4]) && (runs[i, 4] < 223));
				Assert.IsTrue((90 < runs[i, 5]) && (runs[i, 5] < 223));
			}
			#endregion

			#region Test 4
			Assert.AreEqual(0, runs[0, 33]);
			Assert.AreEqual(0, runs[1, 33]);
			#endregion

			Console.WriteLine("done");
		}
	}
}

