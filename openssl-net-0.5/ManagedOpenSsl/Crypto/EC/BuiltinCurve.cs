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
using System.Runtime.InteropServices;
using OpenSSL.Core;

namespace OpenSSL.Crypto.EC
{
	public class BuiltinCurve
	{
		[StructLayout(LayoutKind.Sequential)]
		private struct EC_builtin_curve
		{
			public int nid;
			public string comment;
		}
		
		private Asn1Object obj;
		private string comment;
		
		private BuiltinCurve(int nid, string comment) {
			this.obj = new Asn1Object(nid);
			this.comment = comment;
		}
		
		public Asn1Object Object { get { return this.obj; } }
		public string Comment { get { return this.comment; } }
		
		public static BuiltinCurve[] Get() {
			int count = Native.EC_get_builtin_curves(IntPtr.Zero, 0);
			BuiltinCurve[] curves = new BuiltinCurve[count];
			IntPtr ptr = Native.OPENSSL_malloc(Marshal.SizeOf(typeof(EC_builtin_curve)) * count);
			try {
				Native.ExpectSuccess(Native.EC_get_builtin_curves(ptr, count));
				IntPtr pItem = ptr;
				for (int i = 0; i < count; i++) {
					EC_builtin_curve raw = (EC_builtin_curve)Marshal.PtrToStructure(pItem, typeof(EC_builtin_curve));
					curves[i] = new BuiltinCurve(raw.nid, raw.comment);
					pItem = new IntPtr(pItem.ToInt64() + Marshal.SizeOf(typeof(EC_builtin_curve)));
				}
			}
			finally {
				Native.OPENSSL_free(ptr);
			}
			return curves;
		}
	}
}

