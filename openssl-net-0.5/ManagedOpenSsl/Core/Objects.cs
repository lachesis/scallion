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

namespace OpenSSL.Core
{
	public class Objects
	{
		public class NID
		{
			public static Asn1Object undef = new Asn1Object(0);
			public static Asn1Object X9_62_prime_field = new Asn1Object(406);
			public static Asn1Object X9_62_prime192v1 = new Asn1Object(409);
			public static Asn1Object X9_62_prime192v2 = new Asn1Object(410);
			public static Asn1Object X9_62_prime192v3 = new Asn1Object(411);
			public static Asn1Object X9_62_prime239v1 = new Asn1Object(412);
			public static Asn1Object X9_62_prime239v2 = new Asn1Object(413);
			public static Asn1Object X9_62_prime239v3 = new Asn1Object(414);
			public static Asn1Object X9_62_prime256v1 = new Asn1Object(415);

			public static Asn1Object X9_62_c2tnb191v1 = new Asn1Object(688);
			public static Asn1Object X9_62_c2tnb239v1 = new Asn1Object(694);
			
			public static Asn1Object secp224r1 = new Asn1Object(713);
			public static Asn1Object secp384r1 = new Asn1Object(715);
			public static Asn1Object secp521r1 = new Asn1Object(716);

			public static Asn1Object sect163k1 = new Asn1Object(721);
			public static Asn1Object sect163r2 = new Asn1Object(723);
			public static Asn1Object sect233k1 = new Asn1Object(726);
			public static Asn1Object sect233r1 = new Asn1Object(727);
			public static Asn1Object sect283k1 = new Asn1Object(729);
			public static Asn1Object sect283r1 = new Asn1Object(730);
			public static Asn1Object sect409k1 = new Asn1Object(731);
			public static Asn1Object sect409r1 = new Asn1Object(732);
			public static Asn1Object sect571k1 = new Asn1Object(733);
			public static Asn1Object sect571r1 = new Asn1Object(734);

			public static Asn1Object ipsec4 = new Asn1Object(750);
		}
		
		public class SN
		{
			public static Asn1Object X9_62_prime192v1 = new Asn1Object("prime192v1");
		}
	}
}