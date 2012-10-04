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
	public class DSASignature : Base
	{
		[StructLayout(LayoutKind.Sequential)]
		struct ECDSA_SIG_st
		{
			public IntPtr r;
			public IntPtr s;
		}

		#region Initialization
		internal DSASignature(IntPtr ptr, bool owner) 
			: base(ptr, owner) {
		}
		
		public DSASignature() 
			: base(Native.ExpectNonNull(Native.ECDSA_SIG_new()), true) {
		}
		#endregion

		#region Properties
		private ECDSA_SIG_st Raw {
			get { return (ECDSA_SIG_st)Marshal.PtrToStructure(this.ptr, typeof(ECDSA_SIG_st)); }
			set { Marshal.StructureToPtr(value, this.ptr, false); }
		}

		public BigNumber R {
			get { return new BigNumber(this.Raw.r, false); }
		}

		public BigNumber S {
			get { return new BigNumber(this.Raw.s, false); }
		}
		#endregion

		#region Methods
		#endregion

		#region Overrides
		protected override void OnDispose() {
			Native.ECDSA_SIG_free(this.ptr);
		}
		#endregion
	}
}

