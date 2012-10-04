// Copyright (c) 2006-2012 Frank Laub
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

namespace OpenSSL.Core
{
	/// <summary>
	/// Exposes the RAND_* functions.
	/// </summary>
	public class Random
	{
		/// <summary>
		/// Calls RAND_seed()
		/// </summary>
		/// <param name="seed"></param>
		public static void Seed(byte[] seed)
		{
			Native.RAND_seed(seed, seed.Length);
		}

		/// <summary>
		/// Calls RAND_seed()
		/// </summary>
		/// <param name="seed"></param>
		public static void Seed(string seed)
		{
			byte[] tmp = Encoding.ASCII.GetBytes(seed);
			Native.RAND_seed(tmp, tmp.Length);
		}

		/// <summary>
		/// Calls RAND_pseudo_bytes()
		/// </summary>
		/// <param name="len"></param>
		/// <returns></returns>
		public static byte[] PseudoBytes(int len)
		{
			byte[] buf = new byte[len];
			Native.ExpectSuccess(Native.RAND_pseudo_bytes(buf, buf.Length));
			return buf;
		}

		/// <summary>
		/// Calls RAND_cleanup()
		/// </summary>
		public static void Cleanup()
		{
			Native.RAND_cleanup();
		}

		/// <summary>
		/// Calls RAND_bytes()
		/// </summary>
		/// <param name="len"></param>
		/// <returns></returns>
		public static byte[] Bytes(int len)
		{
			byte[] buf = new byte[len];
			Native.ExpectSuccess(Native.RAND_bytes(buf, len));
			return buf;
		}

		/// <summary>
		/// Calls RAND_add()
		/// </summary>
		/// <param name="buf"></param>
		/// <param name="entropy"></param>
		public static void Add(byte[] buf, double entropy)
		{
			Native.RAND_add(buf, buf.Length, entropy);
		}

		/// <summary>
		/// Calls RAND_load_file()
		/// </summary>
		/// <param name="filename"></param>
		/// <param name="max_bytes"></param>
		public static void LoadFile(string filename, int max_bytes)
		{
			Native.ExpectSuccess(Native.RAND_load_file(filename, max_bytes));
		}

		/// <summary>
		/// Calls RAND_write_file()
		/// </summary>
		/// <param name="filename"></param>
		public static void WriteFile(string filename)
		{
			Native.ExpectSuccess(Native.RAND_write_file(filename));
		}

		/// <summary>
		/// Calls RAND_file_name()
		/// </summary>
		/// <returns></returns>
		public static string GetFilename()
		{
			byte[] buf = new byte[1024];
			return Native.RAND_file_name(buf, (uint)buf.Length);
		}

		/// <summary>
		/// Returns RAND_status()
		/// </summary>
		public static int Status {
			get { return Native.RAND_status(); }
		}

		/// <summary>
		/// Calls RAND_query_egd_bytes()
		/// </summary>
		/// <param name="path"></param>
		/// <param name="buf"></param>
		/// <param name="bytes"></param>
		public static void GatherEntropy(string path, byte[] buf, int bytes)
		{
			Native.ExpectSuccess(Native.RAND_query_egd_bytes(path, buf, bytes));
		}

		/// <summary>
		/// Calls RAND_egd()
		/// </summary>
		/// <param name="path"></param>
		public static void GatherEntropy(string path)
		{
			Native.ExpectSuccess(Native.RAND_egd(path));
		}

		/// <summary>
		/// Calls RAND_egd_bytes()
		/// </summary>
		/// <param name="path"></param>
		/// <param name="bytes"></param>
		public static void GatherEntropy(string path, int bytes)
		{
			Native.ExpectSuccess(Native.RAND_egd_bytes(path, bytes));
		}

		/// <summary>
		/// Calls RAND_poll()
		/// </summary>
		public static void Poll()
		{
			Native.ExpectSuccess(Native.RAND_poll());
		}

		/// <summary>
		/// Calls BN_rand()
		/// </summary>
		/// <param name="bits"></param>
		/// <param name="top"></param>
		/// <param name="bottom"></param>
		/// <returns></returns>
		public static BigNumber Next(int bits, int top, int bottom)
		{
			BigNumber bn = new BigNumber();
			Native.ExpectSuccess(Native.BN_rand(bn.Handle, bits, top, bottom));
			return bn;
		}

		public class Delegates
		{
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate int Seed(IntPtr buf, int num);
	
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate int Bytes([MarshalAs(UnmanagedType.LPArray, SizeParamIndex=1)] byte[] buf, int num);
	
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate void Cleanup();
	
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate void Add(IntPtr buf, int num, double entropy);
	
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate int Status();
		};

		[StructLayout(LayoutKind.Sequential)]
		struct rand_meth_st
		{
			public Delegates.Seed seed;
			public Delegates.Bytes bytes;
			public Delegates.Cleanup cleanup;
			public Delegates.Add add;
			public Delegates.Bytes pseudorand;
			public Delegates.Status status;
		};

		#region Random Method
		public class Method : Base
		{
			#region Data Structures and Variables
			private static IntPtr original;
			private rand_meth_st raw = new rand_meth_st();
			#endregion
			
			#region Initialization			
			static Method() {
				original = Native.ExpectNonNull(Native.RAND_get_rand_method());
			}
			
			public Method() 
				: base(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(rand_meth_st))), true) {
				rand_meth_st raw = (rand_meth_st)Marshal.PtrToStructure(original, typeof(rand_meth_st));
				this.raw.add = raw.add;
				this.raw.bytes = raw.bytes;
				this.raw.seed = raw.seed;
				this.raw.cleanup = raw.cleanup;
				this.raw.pseudorand = raw.pseudorand;
				this.raw.status = raw.status;
			}
			
			~Method() {
				Dispose();
			}
			#endregion
			
			#region Properties
			public Delegates.Seed Seed {
				get { return this.raw.seed; }
				set { this.raw.seed = value; }
			}

			public Delegates.Bytes Bytes {
				get { return this.raw.bytes; }
				set { this.raw.bytes = value; }
			}

			public Delegates.Cleanup Cleanup {
				get { return this.raw.cleanup; }
				set { this.raw.cleanup = value; }
			}

			public Delegates.Add Add {
				get { return this.raw.add; }
				set { this.raw.add = value; }
			}

			public Delegates.Bytes PseudoRand {
				get { return this.raw.pseudorand; }
				set { this.raw.pseudorand = value; }
			}

			public Delegates.Status Status {
				get { return this.raw.status; }
				set { this.raw.status = value; }
			}
			#endregion
			
			#region Methods
			public void Override() {
				Marshal.StructureToPtr(this.raw, this.ptr, false);
				Native.ExpectSuccess(Native.RAND_set_rand_method(this.ptr));
			}
						
			private void Restore() {
				Native.ExpectSuccess(Native.RAND_set_rand_method(original));
			}
			#endregion

			#region IDisposable implementation
			protected override void OnDispose() {
				Restore();
				Marshal.FreeHGlobal(this.ptr);
			}
			#endregion
		};

		#endregion
	}
}
