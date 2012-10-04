// Copyright (c) 2009 Frank Laub
// All rights reserved.

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
using System.Globalization;

namespace OpenSSL.Core
{
	class Asn1DateTime : Base
	{
		internal Asn1DateTime(IntPtr ptr, bool takeOwnership)
			: base(ptr, takeOwnership)
		{ }

		public Asn1DateTime()
			: base(Native.ASN1_TIME_new(), true)
		{ }

		public Asn1DateTime(DateTime dateTime)
			: this()
		{
			this.DateTime = dateTime;
		}

		protected override void OnDispose()
		{
			Native.ASN1_TIME_free(this.ptr);
		}

		public DateTime DateTime
		{
			get
			{
				return ToDateTime(this.ptr);
			}
			set
			{
				long time_t = DateTimeToTimeT(value.ToUniversalTime());
				Native.ASN1_TIME_set(this.ptr, time_t);
			}
		}

		public static DateTime ToDateTime(IntPtr ptr)
		{
			return AsnTimeToDateTime(ptr).ToLocalTime();
		}

		private long DateTimeToTimeT(DateTime value)
		{
			DateTime dt1970 = new DateTime(1970, 1, 1, 0, 0, 0, 0);
			// # of 100 nanoseconds since 1970
			long ticks = (value.Ticks - dt1970.Ticks) / 10000000L;
			return ticks;
		}

		private static DateTime AsnTimeToDateTime(IntPtr ptr)
		{
			string str;
			using (BIO bio = BIO.MemoryBuffer())
			{
				Native.ExpectSuccess(Native.ASN1_UTCTIME_print(bio.Handle, ptr));
				str = bio.ReadString();
			}
			string[] fmts = 
			{ 
				"MMM  d HH:mm:ss yyyy G\\MT",
				"MMM dd HH:mm:ss yyyy G\\MT"
			};
			return DateTime.ParseExact(str, fmts, new DateTimeFormatInfo(), DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
		}
	}
}
