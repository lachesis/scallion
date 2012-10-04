// Copyright (c) 2009 Ben Henderson
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
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using OpenSSL.Core;

namespace OpenSSL.Crypto
{
	/// <summary>
	/// Wraps HMAC
	/// </summary>
	public class HMAC : Base
	{
		#region Raw Structures
		[StructLayout(LayoutKind.Sequential)]
		struct HMAC_CTX
		{
			public IntPtr md;          //const EVP_MD *md;
			public EVP_MD_CTX md_ctx;
			public EVP_MD_CTX i_ctx;
			public EVP_MD_CTX o_ctx;
			public uint key_length;    //unsigned int key_length;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.HMAC_MAX_MD_CBLOCK)]
			public byte[] key;
		}
		#endregion

		#region Initialization
		/// <summary>
		/// Calls OPENSSL_malloc() and then HMAC_CTX_init()
		/// </summary>
		public HMAC()
			: base(IntPtr.Zero, true) {
			// Allocate the context
			this.ptr = Native.OPENSSL_malloc(Marshal.SizeOf(typeof(HMAC_CTX)));
			// Initialize the context
			Native.HMAC_CTX_init(this.ptr);
		}
		#endregion

		#region Methods

		/// <summary>
		/// Calls HMAC()
		/// </summary>
		/// <param name="digest"></param>
		/// <param name="key"></param>
		/// <param name="data"></param>
		/// <returns></returns>
		public static byte[] Digest(MessageDigest digest, byte[] key, byte[] data) {
			byte[] hash_value = new byte[digest.Size];
			uint hash_value_length = Native.EVP_MAX_MD_SIZE;
			Native.HMAC(digest.Handle, key, key.Length, data, data.Length, hash_value, ref hash_value_length);
			return hash_value;
		}

		/// <summary>
		/// Calls HMAC_Init_ex()
		/// </summary>
		/// <param name="key"></param>
		/// <param name="digest"></param>
		public void Init(byte[] key, MessageDigest digest) {
			Native.HMAC_Init_ex(this.ptr, key, key.Length, digest.Handle, IntPtr.Zero);
			this.digest_size = digest.Size;
			this.initialized = true;
		}

		/// <summary>
		/// Calls HMAC_Update()
		/// </summary>
		/// <param name="data"></param>
		public void Update(byte[] data) {
			if (!initialized) {
				throw new Exception("Failed to call Initialize before calling Update");
			}
			Native.HMAC_Update(this.ptr, data, data.Length);
		}

		/// <summary>
		/// Calls HMAC_Update()
		/// </summary>
		/// <param name="data"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		public void Update(byte[] data, int offset, int count) {
			if (!initialized) {
				throw new Exception("Failed to call Initialize before calling Update");
			}
			if (data == null) {
				throw new ArgumentNullException("data");
			}
			if (count <= 0) {
				throw new ArgumentException("count must be greater than 0");
			}
			if (offset < 0) {
				throw new ArgumentException("offset must be 0 or greater");
			}
			if (data.Length < (count - offset)) {
				throw new ArgumentException("invalid length specified.  Count is greater than buffer length.");
			}
			ArraySegment<byte> seg = new ArraySegment<byte>(data, offset, count);
			Native.HMAC_Update(this.ptr, seg.Array, seg.Count);
		}

		/// <summary>
		/// Calls HMAC_Final()
		/// </summary>
		/// <returns></returns>
		public byte[] DigestFinal() {
			if (!initialized) {
				throw new Exception("Failed to call Initialize before calling DigestFinal");
			}
			byte[] hash_value = new byte[digest_size];
			uint hash_value_length = Native.EVP_MAX_MD_SIZE;

			Native.HMAC_Final(this.ptr, hash_value, ref hash_value_length);
			return hash_value;
		}

		#endregion

		#region Overrides
		/// <summary>
		/// Calls HMAC_CTX_cleanup() and then OPENSSL_free()
		/// </summary>
		protected override void OnDispose() {
			// Clean up the context
			Native.HMAC_CTX_cleanup(this.ptr);
			// Free the structure allocation
			Native.OPENSSL_free(this.ptr);
		}
		#endregion

		#region Fields
		private bool initialized = false;
		private int digest_size = 0;
		#endregion
	}
}
