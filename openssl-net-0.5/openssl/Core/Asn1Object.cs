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

namespace OpenSSL.Core
{
	public class Asn1Object
	{
		[StructLayout(LayoutKind.Sequential)]
		struct asn1_object_st
		{
			public string sn;
			public string ln;
			public int nid;
			public int length;
			public byte[] data;
			public int flags;
		}
		
		private int nid;
		
		public Asn1Object(int nid) {
			this.nid = nid;
		}
		
		public Asn1Object(string sn) {
			this.nid = Native.OBJ_sn2nid(sn);
		}

		public int NID { 
			get { return this.nid; } 
		}
		
		public string ShortName {
			get { return Native.OBJ_nid2sn(this.nid); }
		}
		
		public string LongName {
			get { return Native.OBJ_nid2ln(this.nid); }
		}
		
		public static Asn1Object FromShortName(string sn) {
			return new Asn1Object(sn);
		}

		public static Asn1Object FromLongName(string sn) {
			return new Asn1Object(Native.OBJ_ln2nid(sn));
		}
		
		public override bool Equals(object obj) {
			Asn1Object rhs = obj as Asn1Object;
			if (rhs == null)
				return false;
			return this.nid == rhs.nid;
		}
		
		public override int GetHashCode() {
			return this.nid;
		}
	}
}

