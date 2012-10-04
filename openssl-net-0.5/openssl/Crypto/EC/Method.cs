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
using OpenSSL.Core;

namespace OpenSSL.Crypto.EC
{
	public class Method : Base
	{
		#region Initialization
		internal Method(IntPtr ptr, bool owner) 
			: base(ptr, owner) { 
		}
		
		public static Method GFpSimple = new Method(Native.EC_GFp_simple_method(), false);
		public static Method GFpMont = new Method(Native.EC_GFp_mont_method(), false);
		public static Method GFpNist = new Method(Native.EC_GFp_nist_method(), false);
		public static Method GF2mSimple = new Method(Native.EC_GF2m_simple_method(), false);
		#endregion

		#region Properties
		public int FieldType {
			get { return Native.EC_METHOD_get_field_type(this.ptr); }
		}
		#endregion
		
		#region Methods
		#endregion

		#region Overrides
		protected override void OnDispose() {
		}
		#endregion
	}
}

