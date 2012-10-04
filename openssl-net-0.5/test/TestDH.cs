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
using OpenSSL.Core;
using OpenSSL.Crypto;
using System.IO;

namespace UnitTests
{
	[TestFixture]
	public class TestDH : TestBase
	{
		const string rnd_seed = "string to make the random number generator think it has entropy";

		[Test]
		public void TestCase()
		{
			OpenSSL.Core.Random.Seed(rnd_seed);

			BigNumber.GeneratorHandler cb = new BigNumber.GeneratorHandler(this.OnStatus);
			DH a = new DH(64, DH.Generator5, cb, Console.Out);

			DH.CheckCode check = a.Check();
			if ((check & DH.CheckCode.CheckP_NotPrime) != 0)
				Console.WriteLine("p value is not prime");
			if ((check & DH.CheckCode.CheckP_NotSafePrime) != 0)
				Console.WriteLine("p value is not safe prime");
			if ((check & DH.CheckCode.UnableToCheckGenerator) != 0)
				Console.WriteLine("unable to check the generator value");
			if ((check & DH.CheckCode.NotSuitableGenerator) != 0)
				Console.WriteLine("the g value is not a generator");

			Console.WriteLine();
			Console.WriteLine("p    ={0}", a.P);
			Console.WriteLine("g    ={0}", a.G);

			DH b = new DH(a.P, a.G);

			a.NoExpConstantTime = false;
			b.NoExpConstantTime = true;

			a.GenerateKeys();
			Console.WriteLine("pri 1={0}", a.PrivateKey);
			Console.WriteLine("pub 1={0}", a.PublicKey);

			b.GenerateKeys();
			Console.WriteLine("pri 2={0}", b.PrivateKey);
			Console.WriteLine("pub 2={0}", b.PublicKey);

			byte[] aout = a.ComputeKey(b.PublicKey);
			string astr = BitConverter.ToString(aout);
			Console.WriteLine("key1 ={0}", astr);

			byte[] bout = b.ComputeKey(a.PublicKey);
			string bstr = BitConverter.ToString(bout);
			Console.WriteLine("key2 ={0}", bstr);

			if (aout.Length < 4 || astr != bstr)
				throw new Exception("Error in DH routines");

			a.Dispose();
			b.Dispose();
		}

		private int OnStatus(int p, int n, object arg)
		{
			TextWriter cout = (TextWriter)arg;

			switch (p) {
				case 0: cout.Write('.'); break;
				case 1: cout.Write('+'); break;
				case 2: cout.Write('*'); break;
				case 3: cout.WriteLine(); break;
			}

			return 1;
		}
	}
}

