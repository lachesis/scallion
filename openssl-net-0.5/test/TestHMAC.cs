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
using OpenSSL.Core;

namespace UnitTests
{
	[TestFixture]
	public class TestHMAC : TestBase
	{
		public readonly byte[] key = Encoding.ASCII.GetBytes("hmac_key");
		public readonly byte[] small_data = Encoding.ASCII.GetBytes("This is a small data sample");

		// Results
		public readonly string[] md4_results = 
        {
            "D9-82-59-44-94-A9-DD-9C-97-92-DD-1D-20-C2-16-D9",
            "41-20-C5-22-44-0A-00-48-1A-8B-ED-C9-E6-A2-32-FA",
        };
		public readonly string[] md5_results = 
        {
            "3E-06-9C-85-92-FC-14-ED-40-44-3E-B5-E7-8E-62-42",
            "0B-4F-17-84-39-1A-88-0F-A8-1F-94-D2-A0-12-50-94",
        };
		public readonly string[] dss_results = 
        {
            "7B-04-91-96-D1-E0-C2-B0-6E-CB-CE-3D-E9-C8-2C-31-03-40-3E-10",
            "C7-59-5D-DB-C0-7A-70-23-1A-70-B6-CA-75-2B-F3-F5-9A-E6-CA-56",
        };
		public readonly string[] dss1_results = 
        {
            "7B-04-91-96-D1-E0-C2-B0-6E-CB-CE-3D-E9-C8-2C-31-03-40-3E-10",
            "C7-59-5D-DB-C0-7A-70-23-1A-70-B6-CA-75-2B-F3-F5-9A-E6-CA-56",
        };
		public readonly string[] ripemd_results = 
        {
            "A8-65-5E-18-F7-1F-1B-C6-AB-45-4C-71-73-CD-4B-12-2F-9B-3A-8C",
            "CA-62-28-CE-9F-D2-6E-89-2D-F5-16-04-1E-F4-9D-8C-40-35-A6-50",
        };
		public readonly string[] sha_results = 
        {
            "FF-78-05-10-61-96-7D-19-06-F1-7D-DE-0B-FD-CD-31-31-9D-20-84",
            "9F-7D-D1-0E-5C-0B-A8-AD-0E-D9-18-23-64-80-84-78-B8-9B-09-C7",
        };
		public readonly string[] sha1_results = 
        {
            "7B-04-91-96-D1-E0-C2-B0-6E-CB-CE-3D-E9-C8-2C-31-03-40-3E-10",
            "C7-59-5D-DB-C0-7A-70-23-1A-70-B6-CA-75-2B-F3-F5-9A-E6-CA-56",
        };
		public readonly string[] sha224_results = 
        {
            "46-76-7C-76-F1-A3-F1-EB-54-F1-2D-4F-05-89-19-CA-85-1E-96-5B-79-B2-B1-48-F1-9E-B2-A8",
            "7F-38-44-49-17-3C-F5-84-BA-4E-27-0B-37-2C-33-80-D9-EC-D5-B6-C9-5A-E1-A4-AC-69-51-58",
        };
		public readonly string[] sha256_results = 
        {
            "66-9E-3B-51-2F-9D-7A-15-6E-10-69-89-5D-F5-6A-82-BE-DA-A6-D6-AC-F9-8E-66-AC-E6-D6-67-5B-E1-06-EC",
            "84-9A-80-BD-68-9B-78-38-73-85-9E-68-E9-EC-3E-1A-BB-2D-9F-90-1E-AE-C4-D3-07-C8-77-36-1C-B1-8C-38",
        };
		public readonly string[] sha384_results = 
        {
            "0C-3F-83-F0-A4-61-FD-4C-B4-A6-2F-08-45-25-F9-E2-B2-38-85-AF-F3-58-36-8C-C8-89-F7-8B-DC-46-DB-23-C3-CA-4E-1A-43-78-19-33-70-AB-F7-B0-A4-20-17-D0",
            "59-6B-66-8A-CA-F6-73-44-B0-35-C5-B2-75-18-90-0C-86-7C-F0-1D-F5-62-3B-97-C2-7A-C3-A8-55-90-24-03-78-BD-79-CA-81-73-B6-3C-FD-29-B0-86-C5-2B-73-29",
        };
		public readonly string[] sha512_results = 
        {
            "B2-FE-D9-AE-A3-CE-F2-F2-8C-86-6B-79-88-91-23-94-61-39-54-12-DD-C8-4E-D8-D8-31-7C-E4-DF-F2-16-B8-24-D7-90-A6-CB-0C-E9-16-3C-1F-C1-BB-2B-66-AE-3A-EF-6B-45-20-45-E7-FC-E5-B9-28-FD-2F-D1-14-77-B5",
            "6D-10-BB-AC-0B-D7-6D-34-1D-9B-23-F1-4D-CC-14-CE-E4-B4-CD-55-29-EA-35-10-36-E5-C2-A5-59-11-AA-97-66-32-B8-12-92-9E-F2-05-57-01-5C-6D-A8-D0-F0-CB-F6-DF-64-2C-9F-7B-DA-8C-50-2B-07-EA-76-51-85-7E",
        };

		public void VerifyHMAC(MessageDigest digest, string[] results)
		{
			byte[] hash = HMAC.Digest(digest, key, small_data);
			string str = BitConverter.ToString(hash);
			if (str != results[0])
			{
				Console.WriteLine("{0} - Failed to calculate hash on {1}", digest.Name, small_data);
				Console.WriteLine("got {0} instead of {1}", str, results[0]);
			}
			else
			{
				Console.WriteLine("{0} - Test 1 passed.", digest.Name);
			}
			// Compute the large hash
			using (HMAC hmac = new HMAC())
			{
				byte[] buf = Encoding.ASCII.GetBytes(new string('a', 1000));
				hmac.Init(key, digest);
				for (int i = 0; i < 1000; i++)
				{
					hmac.Update(buf);
				}
				hash = hmac.DigestFinal();
				// Check for error
				str = BitConverter.ToString(hash);
				if (str != results[1])
				{
					Console.WriteLine("{0} - Failed to calculate hash on a*1000", digest.Name);
					Console.WriteLine("got {0} instead of {1}", str, results[1]);
				}
				else
				{
					Console.WriteLine("{0} - Test 2 passed.", digest.Name);
				}
			}
		}

		[Test]
		public void TestCase()
		{
			VerifyHMAC(MessageDigest.SHA512, sha512_results);
			VerifyHMAC(MessageDigest.SHA384, sha384_results);
			VerifyHMAC(MessageDigest.SHA256, sha256_results);
			VerifyHMAC(MessageDigest.SHA224, sha224_results);
			VerifyHMAC(MessageDigest.SHA1, sha1_results);
			VerifyHMAC(MessageDigest.DSS1, dss1_results);
			VerifyHMAC(MessageDigest.DSS, dss_results);
			// Shouldn't work in FIPS mode (actually, will crash the program, as the crypto
			// library calls OpenSSLDie() which calls abort()
			if (!FIPS.Enabled) {
				VerifyHMAC(MessageDigest.SHA, sha_results);
				VerifyHMAC(MessageDigest.RipeMD160, ripemd_results);
				VerifyHMAC(MessageDigest.MD5, md5_results);
				VerifyHMAC(MessageDigest.MD4, md4_results);
			}
		}
	}
}

