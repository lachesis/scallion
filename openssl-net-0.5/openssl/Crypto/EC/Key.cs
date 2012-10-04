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
using System.Runtime.InteropServices;

namespace OpenSSL.Crypto.EC
{
	public class Key : BaseCopyableRef<Key>
	{
		public delegate byte[] ComputeKeyHandler(byte[] msg);
		
		[StructLayout(LayoutKind.Sequential)]
		struct ec_key_st 
		{
			public int version;
			public IntPtr group;
			public IntPtr pub_key;
			public IntPtr priv_key;
			public uint enc_flag;
			public int conv_form;
			public int references;
			public IntPtr method_data;
		}
		
		#region Initialization
		internal Key(IntPtr ptr, bool owner) 
			: base(ptr, owner) { 
		}

		public Key()
			: base(Native.ExpectNonNull(Native.EC_KEY_new()), true) {
		}
		
		public static Key FromCurveName(Asn1Object obj) {
			return new Key(Native.ExpectNonNull(Native.EC_KEY_new_by_curve_name(obj.NID)), true);
		}
		#endregion

		#region Properties
		public int Size {
			get { return Native.ECDSA_size(this.ptr); }
		}
		
		public Group Group {
			get { return new Group(Native.ExpectNonNull(Native.EC_KEY_get0_group(this.ptr)), false); }
			set { Native.ExpectSuccess(Native.EC_KEY_set_group(this.ptr, value.Handle)); }
		}
		
		public Point PublicKey {
			get { 
				return new Point(
					this.Group,
					Native.ExpectNonNull(Native.EC_KEY_get0_public_key(this.ptr)), 
					false); 
			}
		}

		public Point PrivateKey {
			get { 
				return new Point(
					this.Group,
					Native.ExpectNonNull(Native.EC_KEY_get0_private_key(this.ptr)), 
					false); 
			}
		}
		
		#endregion

		#region Methods
		public void GenerateKey() {
			Native.ExpectSuccess(Native.EC_KEY_generate_key(this.ptr));
		}
		
		public bool CheckKey() {
			return Native.ExpectSuccess(Native.EC_KEY_check_key(this.ptr)) == 1;
		}
		
		public DSASignature Sign(byte[] digest) {
			IntPtr sig = Native.ExpectNonNull(Native.ECDSA_do_sign(digest, digest.Length, this.ptr));
			return new DSASignature(sig, true);
		}
		
		public uint Sign(int type, byte[] digest, byte[] sig) {
			uint siglen = (uint)sig.Length;
			Native.ExpectSuccess(Native.ECDSA_sign(type, digest, digest.Length, sig, ref siglen, this.ptr));
			return siglen;
		}
		
		public bool Verify(byte[] digest, DSASignature sig) {
			return Native.ECDSA_do_verify(digest, digest.Length, sig.Handle, this.ptr) == 1;
		}
		
		public bool Verify(int type, byte[] digest, byte[] sig) {
			return Native.ECDSA_verify(type, digest, digest.Length, sig, sig.Length, this.ptr) == 1;
		}
		
		public int ComputeKey(Key b, byte[] buf, ComputeKeyHandler kdf) {
			ComputeKeyThunk thunk = new ComputeKeyThunk(kdf);
			return Native.ExpectSuccess(
				Native.ECDH_compute_key(buf, buf.Length, b.PublicKey.Handle, this.ptr, thunk.Wrapper)
			);
		}
		
		class ComputeKeyThunk
		{
			private ComputeKeyHandler kdf;
			
			public ComputeKeyThunk(ComputeKeyHandler kdf) {
				this.kdf = kdf;
			}
			
			public IntPtr Wrapper(byte[] pin, int inlen, IntPtr pout, ref int outlen) {
				byte[] result = kdf(pin);
				if (result.Length > outlen) 
					return IntPtr.Zero;
				Marshal.Copy(result, 0, pout, Math.Min(outlen, result.Length));
				outlen = result.Length;
				return pout;
			}
		}

		#endregion

		#region Overrides
		protected override void OnDispose() {
			Native.EC_KEY_free(this.ptr);
		}

		internal override CryptoLockTypes LockType {
			get { return CryptoLockTypes.CRYPTO_LOCK_EC; }
		}

		internal override Type RawReferenceType {
			get { return typeof(ec_key_st); }
		}
		#endregion
	}
}

