// Copyright (c) 2006-2007 Frank Laub
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
using System.IO;
using OpenSSL.Crypto;

namespace OpenSSL.Core
{
	/// <summary>
	/// Encapsulates the BIO_* functions.
	/// </summary>
	public class BIO : Base
	{
		#region Initialization
		internal BIO(IntPtr ptr, bool owner) : base(ptr, owner) { }

		/// <summary>
		/// Calls BIO_new_mem_buf() from the specified buffer.
		/// </summary>
		/// <param name="buf"></param>
		public BIO(byte[] buf)
			: base(Native.ExpectNonNull(Native.BIO_new_mem_buf(buf, buf.Length)), true)
		{
		}

		/// <summary>
		/// Calls BIO_new_mem_buf() from the specified string.
		/// </summary>
		/// <param name="str"></param>
		public BIO(string str)
			: this(Encoding.ASCII.GetBytes(str))
		{
		}

		/// <summary>
		/// Calls BIO_new(BIO_s_mem())
		/// </summary>
		/// <param name="takeOwnership"></param>
		/// <returns></returns>
		public static BIO MemoryBuffer(bool takeOwnership)
		{
			IntPtr ptr = Native.ExpectNonNull(Native.BIO_new(Native.BIO_s_mem()));
			return new BIO(ptr, takeOwnership);
		}

		/// <summary>
		/// Factory method that calls BIO_new() with BIO_s_mem()
		/// </summary>
		/// <returns></returns>
		public static BIO MemoryBuffer()
		{
			return MemoryBuffer(true);
		}

		/// <summary>
		/// Factory method that calls BIO_new_file()
		/// </summary>
		/// <param name="filename"></param>
		/// <param name="mode"></param>
		/// <returns></returns>
		public static BIO File(string filename, string mode)
		{
			IntPtr ptr = Native.ExpectNonNull(Native.BIO_new_file(filename, mode));
			return new BIO(ptr, true);
		}

		private const int FD_STDIN = 0;
		private const int FD_STDOUT = 1;
		private const int FD_STDERR = 2;

		/// <summary>
		/// Factory method that calls BIO_new() with BIO_f_md()
		/// </summary>
		/// <param name="md"></param>
		/// <returns></returns>
		public static BIO MessageDigest(MessageDigest md)
		{
			IntPtr ptr = Native.ExpectNonNull(Native.BIO_new(Native.BIO_f_md()));
			Native.BIO_set_md(ptr, md.Handle);
			return new BIO(ptr, true);
		}

		//public static BIO MessageDigestContext(MessageDigestContext ctx)
		//{
		//    IntPtr ptr = Native.ExpectNonNull(Native.BIO_new(Native.BIO_f_md()));
		//    //IntPtr ptr = Native.ExpectNonNull(Native.BIO_new(Native.BIO_f_null()));
		//    Native.BIO_set_md_ctx(ptr, ctx.Handle);
		//    return new BIO(ptr);
		//}
		#endregion

		#region Properties
		/// <summary>
		/// Returns BIO_number_read()
		/// </summary>
		public uint NumberRead
		{
			get { return Native.BIO_number_read(this.Handle); }
		}

		/// <summary>
		/// Returns BIO_number_written()
		/// </summary>
		public uint NumberWritten
		{
			get { return Native.BIO_number_written(this.Handle); }
		}

		/// <summary>
		/// Returns number of bytes buffered in the BIO - calls BIO_ctrl_pending
		/// </summary>
		public uint BytesPending
		{
			get { return Native.BIO_ctrl_pending(this.Handle); }
		}

		#endregion

		#region Methods

		/// <summary>
		/// BIO Close Options
		/// </summary>
		public enum CloseOption
		{
			/// <summary>
			/// Don't close on free
			/// </summary>
			NoClose = 0,
			/// <summary>
			/// Close on freee
			/// </summary>
			Close = 1
		}

		/// <summary>
		/// Calls BIO_set_close()
		/// </summary>
		/// <param name="opt"></param>
		public void SetClose(CloseOption opt)
		{
			Native.BIO_set_close(this.ptr, (int)opt);
		}

		/// <summary>
		/// Calls BIO_push()
		/// </summary>
		/// <param name="bio"></param>
		public void Push(BIO bio)
		{
			Native.ExpectNonNull(Native.BIO_push(this.ptr, bio.Handle));
		}

		/// <summary>
		/// Calls BIO_write()
		/// </summary>
		/// <param name="buf"></param>
		public void Write(byte[] buf)
		{
			if (Native.BIO_write(this.ptr, buf, buf.Length) != buf.Length)
				throw new OpenSslException();
		}

		/// <summary>
		/// Calls BIO_write()
		/// </summary>
		/// <param name="buf"></param>
		/// <param name="len"></param>
		public void Write(byte[] buf, int len)
		{
			if (Native.BIO_write(this.ptr, buf, len) != len)
				throw new OpenSslException();
		}

		/// <summary>
		/// Calls BIO_write()
		/// </summary>
		/// <param name="value"></param>
		public void Write(byte value)
		{
			byte[] buf = new byte[1];
			buf[0] = value;
			Write(buf);
		}

		/// <summary>
		/// Calls BIO_write()
		/// </summary>
		/// <param name="value"></param>
		public void Write(ushort value)
		{
			MemoryStream ms = new MemoryStream();
			BinaryWriter br = new BinaryWriter(ms);
			br.Write(value);
			byte[] buf = ms.ToArray();
			Write(buf);
		}

		/// <summary>
		/// Calls BIO_write()
		/// </summary>
		/// <param name="value"></param>
		public void Write(uint value)
		{
			MemoryStream ms = new MemoryStream();
			BinaryWriter br = new BinaryWriter(ms);
			br.Write(value);
			byte[] buf = ms.ToArray();
			Write(buf);
		}

		/// <summary>
		/// Calls BIO_puts()
		/// </summary>
		/// <param name="str"></param>
		public void Write(string str)
		{
			byte[] buf = Encoding.ASCII.GetBytes(str);
			if (Native.BIO_puts(this.ptr, buf) != buf.Length)
				throw new OpenSslException();
		}

		/// <summary>
		/// Calls BIO_read()
		/// </summary>
		/// <param name="count"></param>
		/// <returns></returns>
		public ArraySegment<byte> ReadBytes(int count)
		{
			byte[] buf = new byte[count];
			int ret = Native.BIO_read(this.ptr, buf, buf.Length);
			if (ret < 0)
				throw new OpenSslException();

			return new ArraySegment<byte>(buf, 0, ret);
		}

		/// <summary>
		/// Calls BIO_gets()
		/// </summary>
		/// <returns></returns>
		public string ReadString()
		{
			StringBuilder sb = new StringBuilder();
			const int BLOCK_SIZE = 64;
			byte[] buf = new byte[BLOCK_SIZE];
			int ret = 0;
			while (true)
			{
				ret = Native.BIO_gets(this.ptr, buf, buf.Length);
				if (ret == 0)
					break;
				if (ret < 0)
					throw new OpenSslException();

				sb.Append(Encoding.ASCII.GetString(buf, 0, ret));
			}
			return sb.ToString();
		}

		/// <summary>
		/// Returns the MessageDigestContext if this BIO's type if BIO_f_md()
		/// </summary>
		/// <returns></returns>
		public MessageDigestContext GetMessageDigestContext()
		{
			return new MessageDigestContext(this);
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls BIO_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.BIO_free(this.ptr);
		}

		#endregion
	}
}
