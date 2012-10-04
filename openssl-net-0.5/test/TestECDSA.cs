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
using OpenSSL.Core;
using Random = OpenSSL.Core.Random;
using System.Runtime.InteropServices;
using OpenSSL.Crypto;
using System.Text;
using OpenSSL.Crypto.EC;

namespace UnitTests
{
	[TestFixture]
	public class TestECDSA : TestBase
	{
		private void x9_62_test_internal(Asn1Object obj, string r_in, string s_in) {
			byte[] message = Encoding.ASCII.GetBytes("abc");
			
			using(MessageDigestContext md_ctx = new MessageDigestContext(MessageDigest.ECDSA)) {
				byte[] digest = md_ctx.Digest(message);
				
				Console.Write("testing {0}: ", obj.ShortName);
	
				using(Key key = Key.FromCurveName(obj)) {
					key.GenerateKey();
					Console.Write(".");
					using(DSASignature signature = key.Sign(digest)) {
						Console.Write(".");
						BigNumber r = BigNumber.FromDecimalString(r_in);
						BigNumber s = BigNumber.FromDecimalString(s_in);
						Assert.AreEqual(r, signature.R);
						Assert.AreEqual(s, signature.S);
						Console.Write(".");
						Assert.IsTrue(key.Verify(digest, signature));
						Console.Write(".");
					}
				}
			}
			Console.WriteLine(" ok");
		}
		
		[Test]
		public void x9_62_tests() {
			Random.Seed("string to make the random number generator think it has entropy");

			Console.WriteLine("some tests from X9.62");
			
			x9_62_test_internal(Objects.NID.X9_62_prime192v1, 
			                    "3342403536405981729393488334694600415596881826869351677613", 
			                    "5735822328888155254683894997897571951568553642892029982342");
			x9_62_test_internal(Objects.NID.X9_62_prime239v1, 
			                    "308636143175167811492622547300668018854959378758531778147462058306432176", 
			                    "323813553209797357708078776831250505931891051755007842781978505179448783");
			x9_62_test_internal(Objects.NID.X9_62_c2tnb191v1, 
			                    "87194383164871543355722284926904419997237591535066528048", 
			                    "308992691965804947361541664549085895292153777025772063598");
			x9_62_test_internal(Objects.NID.X9_62_c2tnb239v1, 
			                    "21596333210419611985018340039034612628818151486841789642455876922391552", 
			                    "197030374000731686738334997654997227052849804072198819102649413465737174");
		}

		[Test]
		public void test_builtin() {
			/* fill digest values with some random data */
			byte[] digest = Random.PseudoBytes(20);
			byte[] wrong_digest = Random.PseudoBytes(20);

			/* create and verify a ecdsa signature with every availble curve
			 * (with ) */
			Console.WriteLine("testing ECDSA_sign() and ECDSA_verify() with some internal curves:");
			
			/* get a list of all internal curves */
			BuiltinCurve[] curves = BuiltinCurve.Get();
			
			/* now create and verify a signature for every curve */
			foreach (BuiltinCurve curve in curves) {
				if (curve.Object.NID == Objects.NID.ipsec4.NID)
					continue;
				
				/* create new ecdsa key (== EC_KEY) */
				using(Key eckey = new Key()) {

					using(Group group = Group.FromCurveName(curve.Object)) {
						eckey.Group = group;
					}
					
					if (eckey.Group.Degree < 160) {
						/* drop the curve */ 
						continue;
					}
					
					Console.Write("{0}: ", curve.Object.ShortName);
					
					/* create key */
					eckey.GenerateKey();
					
					/* create second key */
					using(Key wrong_eckey = new Key()) {
						using(Group group = Group.FromCurveName(curve.Object)) {
							wrong_eckey.Group = group;
						}
						
						wrong_eckey.GenerateKey();
						Console.Write(".");
						
						/* check key */
						Assert.IsTrue(eckey.CheckKey());
						Console.Write(".");
						
						/* create signature */
						byte[] signature = new byte[eckey.Size];
						eckey.Sign(0, digest, signature);
						Console.Write(".");
						
						/* verify signature */
						Assert.IsTrue(eckey.Verify(0, digest, signature));
						Console.Write(".");
						
						/* verify signature with the wrong key */
						Assert.IsFalse(wrong_eckey.Verify(0, digest, signature));
						Console.Write(".");
						
						/* wrong digest */
						Assert.IsFalse(eckey.Verify(0, wrong_digest, signature));
						Console.Write(".");
						
						Console.WriteLine(" ok");						
					}
				}
			}
		}
	}
}

