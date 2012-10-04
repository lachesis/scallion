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
using System.Runtime.InteropServices;

namespace OpenSSL.Core
{
	/// <summary>
	/// V_CRYPTO_MDEBUG_*
	/// </summary>
	[Flags]
	public enum DebugOptions
	{
		/// <summary>
		/// V_CRYPTO_MDEBUG_TIME 
		/// </summary>
		Time = 0x01,

		/// <summary>
		/// V_CRYPTO_MDEBUG_THREAD
		/// </summary>
		Thread = 0x02,

		/// <summary>
		/// V_CRYPTO_MDEBUG_ALL 
		/// </summary>
		All = Time | Thread,
	}

	/// <summary>
	/// CRYPTO_MEM_CHECK_*
	/// </summary>
	public enum MemoryCheck
	{
		/// <summary>
		/// CRYPTO_MEM_CHECK_OFF 
		/// for applications
		/// </summary>
		Off = 0x00,

		/// <summary>
		/// CRYPTO_MEM_CHECK_ON 
		/// for applications
		/// </summary>
		On = 0x01,

		/// <summary>
		/// CRYPTO_MEM_CHECK_ENABLE
		/// for library-internal use
		/// </summary>
		Enable = 0x02,

		/// <summary>
		/// CRYPTO_MEM_CHECK_DISABLE
		/// for library-internal use
		/// </summary>
		Disable = 0x03,
	}

	/// <summary>
	/// Exposes the CRYPTO_* functions
	/// </summary>
	public class CryptoUtil
	{
		/// <summary>
		/// Returns MD2_options()
		/// </summary>
		public static string MD2_Options
		{
			get { return Native.MD2_options(); }
		}

		/// <summary>
		/// Returns RC4_options()
		/// </summary>
		public static string RC4_Options
		{
			get { return Native.RC4_options(); }
		}

		/// <summary>
		/// Returns DES_options()
		/// </summary>
		public static string DES_Options
		{
			get { return Native.DES_options(); }
		}

		/// <summary>
		/// Returns idea_options()
		/// </summary>
		public static string Idea_Options
		{
			get { return Native.idea_options(); }
		}

		/// <summary>
		/// Returns BF_options()
		/// </summary>
		public static string Blowfish_Options
		{
			get { return Native.BF_options(); }
		}

		/// <summary>
		/// Calls CRYPTO_malloc_debug_init()
		/// </summary>
		public static void MallocDebugInit()
		{
			Native.CRYPTO_malloc_debug_init();
		}

		/// <summary>
		/// Calls CRYPTO_dbg_set_options()
		/// </summary>
		/// <param name="options"></param>
		public static void SetDebugOptions(DebugOptions options)
		{
			Native.CRYPTO_dbg_set_options((int)options);
		}

		/// <summary>
		/// Calls CRYPTO_mem_ctrl()
		/// </summary>
		/// <param name="options"></param>
		public static void SetMemoryCheck(MemoryCheck options)
		{
			Native.CRYPTO_mem_ctrl((int)options);
		}

		/// <summary>
		/// Calls CRYPTO_cleanup_all_ex_data()
		/// </summary>
		public static void Cleanup()
		{
			Native.CRYPTO_cleanup_all_ex_data();
		}

		/// <summary>
		/// Calls ERR_remove_state()
		/// </summary>
		/// <param name="value"></param>
		public static void RemoveState(uint value)
		{
			Native.ERR_remove_state(value);
		}

		/// <summary>
		/// CRYPTO_MEM_LEAK_CB
		/// </summary>
		/// <param name="order"></param>
		/// <param name="file"></param>
		/// <param name="line"></param>
		/// <param name="num_bytes"></param>
		/// <param name="addr"></param>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void MemoryLeakHandler(uint order, IntPtr file, int line, int num_bytes, IntPtr addr);

		/// <summary>
		/// Calls CRYPTO_mem_leaks_cb()
		/// </summary>
		/// <param name="callback"></param>
		public static void CheckMemoryLeaks(MemoryLeakHandler callback)
		{
			Native.CRYPTO_mem_leaks_cb(callback);
		}
	}
}
