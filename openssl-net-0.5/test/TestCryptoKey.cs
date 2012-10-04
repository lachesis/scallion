// Copyright (c) 2009-2011 Frank Laub
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
using OpenSSL;
using NUnit.Framework;
using OpenSSL.Core;
using OpenSSL.Crypto;

namespace UnitTests
{
	[TestFixture]
	public class TestCryptoKey : TestBase
	{
		[Test]
		public void CanCreateAndDispose()
		{
			using (CryptoKey key = new CryptoKey())
			{
			}
		}

		[Test]
		public void CanCompare()
		{
			using (DSA dsa = new DSA(true))
			{
				using (CryptoKey lhs = new CryptoKey(dsa))
				{
					Assert.AreEqual(lhs, lhs);
					using (CryptoKey rhs = new CryptoKey(dsa))
					{
						Assert.AreEqual(lhs, rhs);
					}

					using (DSA dsa2 = new DSA(true))
					{
						using (CryptoKey other = new CryptoKey(dsa2))
						{
							Assert.IsFalse(lhs == other);
						}
					}
				}
			}

			using (RSA rsa = new RSA())
			{
				rsa.GenerateKeys(1024, BigNumber.One, null, null);
				using (CryptoKey lhs = new CryptoKey(rsa))
				{
					Assert.AreEqual(lhs, lhs);
					using (CryptoKey rhs = new CryptoKey(rsa))
					{
						Assert.AreEqual(lhs, rhs);
					}

					using (RSA rsa2 = new RSA())
					{
						rsa2.GenerateKeys(1024, BigNumber.One, null, null);
						using (CryptoKey other = new CryptoKey(rsa2))
						{
							Assert.IsFalse(lhs == other);
						}
					}
				}
			}
		}
	
		[Test]
		[Ignore("Not implemented yet")]
		public void CanCreateFromPublicKey()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanCreateFromPrivateKey()
		{
		}

		[Test]
		public void CanCreateFromDSA()
		{
			using (DSA dsa = new DSA(true))
			{
				using (CryptoKey key = new CryptoKey(dsa))
				{
					Assert.AreEqual(CryptoKey.KeyType.DSA, key.Type);
					Assert.AreEqual(dsa.Size, key.Size);
				}
			}

			using (CryptoKey key = new CryptoKey(new DSA(false)))
			{
				Assert.AreEqual(CryptoKey.KeyType.DSA, key.Type);
			}
		}

		[Test]
		public void CanCreateFromRSA()
		{
			using (RSA rsa = new RSA())
			{
				rsa.GenerateKeys(1024, BigNumber.One, null, null);
				using (CryptoKey key = new CryptoKey(rsa))
				{
					Assert.AreEqual(CryptoKey.KeyType.RSA, key.Type);
					Assert.AreEqual(rsa.Size, key.Size);
				}
			}
		}

		[Test]
		public void CanCreateFromDH()
		{
			using (DH dh = new DH())
			{
				dh.GenerateKeys();
				using (CryptoKey key = new CryptoKey(dh)) {
					Assert.AreEqual(CryptoKey.KeyType.DH, key.Type);
				}
			}
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanAssign()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanWritePrivateKey()
		{
		}
	}
}
