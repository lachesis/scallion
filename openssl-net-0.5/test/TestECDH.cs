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
using NUnit.Framework;
using OpenSSL.Crypto.EC;
using OpenSSL.Core;
using OpenSSL.Crypto;
using System.Runtime.InteropServices;

namespace UnitTests
{
	[TestFixture]
	public class TestECDH : TestBase
	{
		private byte[] KDF1_SHA1(byte[] msg) {
			using (MessageDigestContext mdc = new MessageDigestContext(MessageDigest.SHA1)) {
				return mdc.Digest(msg);
			}
		}
		
		private bool Compare(byte[] a, byte[] b) {
			for (int i = 0; i < a.Length; i++) {
				if (a[i] != b[i]) 
					return false;
			}
			return true;
		}
		
		private void test_ecdh_curve(Asn1Object obj, string text, BigNumber.Context ctx) {
			Key a = Key.FromCurveName(obj);
			Key b = Key.FromCurveName(obj);
			BigNumber x_a = new BigNumber();
			BigNumber y_a = new BigNumber();
			BigNumber x_b = new BigNumber();
			BigNumber y_b = new BigNumber();
			
			try {
				Console.Write("Testing key generation with {0}", text);
				
				a.GenerateKey();
				if (a.Group.Method.FieldType == Objects.NID.X9_62_prime_field.NID) {
					a.PublicKey.GetAffineCoordinatesGFp(x_a, y_a, ctx);
				}
				else {
					a.PublicKey.GetAffineCoordinatesGF2m(x_a, y_a, ctx);
				}
				Console.Write(".");
				
				b.GenerateKey();
				if (b.Group.Method.FieldType == Objects.NID.X9_62_prime_field.NID) {
					b.PublicKey.GetAffineCoordinatesGFp(x_b, y_b, ctx);
				}
				else {
					b.PublicKey.GetAffineCoordinatesGF2m(x_b, y_b, ctx);
				}
				Console.Write(".");
				
				byte[] abuf = new byte[MessageDigest.SHA1.Size];
				int aout = a.ComputeKey(b, abuf, KDF1_SHA1);
				Console.Write(".");
				
				byte[] bbuf = new byte[MessageDigest.SHA1.Size];
				int bout = b.ComputeKey(a, bbuf, KDF1_SHA1);
				Console.Write(".");
				
				Assert.Greater(aout, 4);
				Assert.AreEqual(aout, bout);
				Assert.IsTrue(Compare(abuf, bbuf));

				Console.Write(" ok");
			}
			finally {
				a.Dispose();
				b.Dispose();
				x_a.Dispose();
				y_a.Dispose();
				x_b.Dispose();
				y_b.Dispose();
			}
			
			Console.WriteLine();
		}

		[Test]
		public void TestCase() {
			using (BigNumber.Context ctx = new BigNumber.Context()) {
				/* NIST PRIME CURVES TESTS */
				test_ecdh_curve(Objects.NID.X9_62_prime192v1, "NIST Prime-Curve P-192", ctx);
				test_ecdh_curve(Objects.NID.secp224r1, "NIST Prime-Curve P-224", ctx);
				test_ecdh_curve(Objects.NID.X9_62_prime256v1, "NIST Prime-Curve P-256", ctx);
				test_ecdh_curve(Objects.NID.secp384r1, "NIST Prime-Curve P-384", ctx);
				test_ecdh_curve(Objects.NID.secp521r1, "NIST Prime-Curve P-521", ctx);
				/* NIST BINARY CURVES TESTS */
				test_ecdh_curve(Objects.NID.sect163k1, "NIST Binary-Curve K-163", ctx);
				test_ecdh_curve(Objects.NID.sect163r2, "NIST Binary-Curve B-163", ctx);
				test_ecdh_curve(Objects.NID.sect233k1, "NIST Binary-Curve K-233", ctx);
				test_ecdh_curve(Objects.NID.sect233r1, "NIST Binary-Curve B-233", ctx);
				test_ecdh_curve(Objects.NID.sect283k1, "NIST Binary-Curve K-283", ctx);
				test_ecdh_curve(Objects.NID.sect283r1, "NIST Binary-Curve B-283", ctx);
				test_ecdh_curve(Objects.NID.sect409k1, "NIST Binary-Curve K-409", ctx);
				test_ecdh_curve(Objects.NID.sect409r1, "NIST Binary-Curve B-409", ctx);
				test_ecdh_curve(Objects.NID.sect571k1, "NIST Binary-Curve K-571", ctx);
				test_ecdh_curve(Objects.NID.sect571r1, "NIST Binary-Curve B-571", ctx);
			}
		}
	}
}

