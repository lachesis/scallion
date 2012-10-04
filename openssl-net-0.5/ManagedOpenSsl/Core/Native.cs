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

using System.Text;
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Reflection;
using System.Collections.Generic;
using System.Threading;

namespace OpenSSL.Core
{
	/// <summary>
	/// 
	/// </summary>
	public static class FIPS
	{
		/// <summary>
		/// 
		/// </summary>
		public static bool Enabled { get; set; }
	}

	internal enum CryptoLockTypes
	{
		CRYPTO_LOCK_ERR = 1,
		CRYPTO_LOCK_EX_DATA = 2,
		CRYPTO_LOCK_X509 = 3,
		CRYPTO_LOCK_X509_INFO = 4,
		CRYPTO_LOCK_X509_PKEY = 5,
		CRYPTO_LOCK_X509_CRL = 6,
		CRYPTO_LOCK_X509_REQ = 7,
		CRYPTO_LOCK_DSA = 8,
		CRYPTO_LOCK_RSA = 9,
		CRYPTO_LOCK_EVP_PKEY = 10,
		CRYPTO_LOCK_X509_STORE = 11,
		CRYPTO_LOCK_SSL_CTX = 12,
		CRYPTO_LOCK_SSL_CERT = 13,
		CRYPTO_LOCK_SSL_SESSION = 14,
		CRYPTO_LOCK_SSL_SESS_CERT = 15,
		CRYPTO_LOCK_SSL = 16,
		CRYPTO_LOCK_SSL_METHOD = 17,
		CRYPTO_LOCK_RAND = 18,
		CRYPTO_LOCK_RAND2 = 19,
		CRYPTO_LOCK_MALLOC = 20,
		CRYPTO_LOCK_BIO = 21,
		CRYPTO_LOCK_GETHOSTBYNAME = 22,
		CRYPTO_LOCK_GETSERVBYNAME = 23,
		CRYPTO_LOCK_READDIR = 24,
		CRYPTO_LOCK_RSA_BLINDING = 25,
		CRYPTO_LOCK_DH = 26,
		CRYPTO_LOCK_MALLOC2 = 27,
		CRYPTO_LOCK_DSO = 28,
		CRYPTO_LOCK_DYNLOCK = 29,
		CRYPTO_LOCK_ENGINE = 30,
		CRYPTO_LOCK_UI = 31,
		CRYPTO_LOCK_ECDSA = 32,
		CRYPTO_LOCK_EC = 33,
		CRYPTO_LOCK_ECDH = 34,
		CRYPTO_LOCK_BN = 35,
		CRYPTO_LOCK_EC_PRE_COMP = 36,
		CRYPTO_LOCK_STORE = 37,
		CRYPTO_LOCK_COMP = 38,
		CRYPTO_LOCK_FIPS = 39,
		CRYPTO_LOCK_FIPS2 = 40,
		CRYPTO_NUM_LOCKS = 41,
	}

	/// <summary>
	/// static class for initialize OpenSSL/Crypto libraries for threading
	/// </summary>
	public class ThreadInitialization
	{
		/// <summary>
		/// Calls Native.InitializeThreads()
		/// </summary>
		public static void InitializeThreads()
		{
			Native.InitializeThreads();
		}

		/// <summary>
		/// Calls Native.UninitializeThreads()
		/// </summary>
		public static void UninitializeThreads()
		{
			Native.UninitializeThreads();
		}
	}

	/// <summary>
	/// This is the low-level C-style interface to the crypto API.
	/// Use this interface with caution.
	/// </summary>
	internal class Native
	{
		/// <summary>
		/// This is the name of the DLL that P/Invoke loads and tries to bind all of
		/// these native functions to.
		/// </summary>
		const string DLLNAME = "libeay32";
		const string SSLDLLNAME = "ssleay32";

		#region Delegates
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int pem_password_cb(IntPtr buf, int size, int rwflag, IntPtr userdata);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int GeneratorHandler(int p, int n, IntPtr arg);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void ObjectNameHandler(IntPtr name, IntPtr arg);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void CRYPTO_locking_callback(int mode, int type, string file, int line);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate uint CRYPTO_id_callback();

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int VerifyCertCallback(int ok, IntPtr x509_store_ctx);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int client_cert_cb(IntPtr ssl, out IntPtr x509, out IntPtr pkey);

		#endregion

		#region Initialization
		static Native()
		{
			Version lib = Version.Library;
			Version wrapper = Version.Wrapper;
			uint mmf = lib.Raw & 0xfffff000;
			if (mmf != wrapper.Raw)
				throw new Exception(string.Format("Invalid version of {0}, expecting {1}, got: {2}",
					DLLNAME, wrapper, lib));

			// Enable FIPS mode
			if (FIPS.Enabled)
			{
				if (FIPS_mode_set(1) == 0)
				{
					throw new Exception("Failed to initialize FIPS mode");
				}
			}

			ERR_load_crypto_strings();
			SSL_load_error_strings();

			OPENSSL_add_all_algorithms_noconf();

			// Initialize SSL library
			Native.ExpectSuccess(SSL_library_init());

			byte[] seed = new byte[128];
			RandomNumberGenerator rng = RandomNumberGenerator.Create();
			rng.GetBytes(seed);
			RAND_seed(seed, seed.Length);
		}

		public static void InitializeThreads()
		{
			// Initialize the threading locks
			int nLocks = CRYPTO_num_locks();
			lock_objects = new List<object>(nLocks);
			for (int i = 0; i < nLocks; i++)
			{
				object obj = new object();
				lock_objects.Add(obj);
			}
			// Initialize the internal thread id stack
			threadIDs = new System.Collections.Generic.Stack<uint>();
			// Initialize the delegate for the locking callback
			CRYPTO_locking_callback_delegate = new CRYPTO_locking_callback(LockingCallback);
			CRYPTO_set_locking_callback(CRYPTO_locking_callback_delegate);
			// Initialze the thread id callback
			CRYPTO_id_callback_delegate = new CRYPTO_id_callback(ThreadIDCallback);
			CRYPTO_set_id_callback(CRYPTO_id_callback_delegate);
		}

		public static void UninitializeThreads()
		{
			// Cleanup the thread lock objects
			CRYPTO_set_locking_callback(null);
			lock_objects.Clear();
			CRYPTO_set_id_callback(null);
			// Clean up error state for each thread that was used by OpenSSL
			if (threadIDs != null)
			{
				foreach (uint id in threadIDs)
				{
					Native.ERR_remove_state(id);
				}
			}
		}

		#endregion

		#region Version
		public const uint Wrapper = 0x10000000;

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string SSLeay_version(int type);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint SSLeay();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string BN_options();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string MD2_options();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string RC4_options();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string DES_options();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string idea_options();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string BF_options();

		#endregion

		#region Threading
		private static List<object> lock_objects;
		private static CRYPTO_locking_callback CRYPTO_locking_callback_delegate;
		private static CRYPTO_id_callback CRYPTO_id_callback_delegate;

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_set_id_callback(CRYPTO_id_callback cb);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_set_locking_callback(CRYPTO_locking_callback cb);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int CRYPTO_num_locks();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int CRYPTO_add_lock(IntPtr ptr, int amount, CryptoLockTypes type, string file, int line);

		public const int CRYPTO_LOCK = 1;

		public static void LockingCallback(int mode, int type, string file, int line)
		{
			if ((mode & CRYPTO_LOCK) == CRYPTO_LOCK)
			{
				Monitor.Enter(lock_objects[type]);
			}
			else
			{
				Monitor.Exit(lock_objects[type]);
			}
		}

		private static System.Collections.Generic.Stack<uint> threadIDs;

		public static uint ThreadIDCallback()
		{
			uint threadID = (uint)Thread.CurrentThread.ManagedThreadId;
			if (!threadIDs.Contains(threadID))
			{
				threadIDs.Push(threadID);
			}
			return threadID;
		}

		#endregion

		#region CRYPTO
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void OPENSSL_add_all_algorithms_noconf();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void OPENSSL_add_all_algorithms_conf();

		/// <summary>
		/// #define OPENSSL_free(addr) CRYPTO_free(addr)
		/// </summary>
		/// <param name="p"></param>
		public static void OPENSSL_free(IntPtr p)
		{
			CRYPTO_free(p);
		}

		/// <summary>
		/// #define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)
		/// </summary>
		/// <param name="cbSize"></param>
		/// <returns></returns>
		public static IntPtr OPENSSL_malloc(int cbSize)
		{
			return CRYPTO_malloc(cbSize, Assembly.GetExecutingAssembly().FullName, 0);
		}

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_free(IntPtr p);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr CRYPTO_malloc(int num, string file, int line);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr CRYPTO_realloc(IntPtr ptr, int num, string file, int line);

		private static MallocFunctionPtr ptr_CRYPTO_dbg_malloc = CRYPTO_dbg_malloc;
		private static ReallocFunctionPtr ptr_CRYPTO_dbg_realloc = CRYPTO_dbg_realloc;
		private static FreeFunctionPtr ptr_CRYPTO_dbg_free = CRYPTO_dbg_free;
		private static SetOptionsFunctionPtr ptr_CRYPTO_dbg_set_options = CRYPTO_dbg_set_options;
		private static GetOptionsFunctionPtr ptr_CRYPTO_dbg_get_options = CRYPTO_dbg_get_options;

		//!! - Expose the default CRYPTO_malloc_debug_init() - this method hooks up the default 
		//!! - debug functions in the crypto library, this allows us to utilize the MemoryTracker
		//!! - on non-Windows systems as well.
		public static void CRYPTO_malloc_debug_init() {
			CRYPTO_set_mem_debug_functions(
				ptr_CRYPTO_dbg_malloc,
				ptr_CRYPTO_dbg_realloc,
				ptr_CRYPTO_dbg_free,
				ptr_CRYPTO_dbg_set_options,
				ptr_CRYPTO_dbg_get_options);
		}


		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void MallocFunctionPtr(IntPtr addr, int num, IntPtr file, int line, int before_p);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void ReallocFunctionPtr(IntPtr addr1, IntPtr addr2, int num, IntPtr file, int line, int before_p);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void FreeFunctionPtr(IntPtr addr, int before_p);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void SetOptionsFunctionPtr(int bits);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int GetOptionsFunctionPtr();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_dbg_malloc(IntPtr addr, int num, IntPtr file, int line, int before_p);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_dbg_realloc(IntPtr addr1, IntPtr addr2, int num, IntPtr file, int line, int before_p);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_dbg_free(IntPtr addr, int before_p);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_dbg_set_options(int bits);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int CRYPTO_dbg_get_options();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int CRYPTO_set_mem_debug_functions(
			MallocFunctionPtr m, 
			ReallocFunctionPtr r, 
			FreeFunctionPtr f, 
			SetOptionsFunctionPtr so, 
			GetOptionsFunctionPtr go);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int CRYPTO_mem_ctrl(int mode);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_cleanup_all_ex_data();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_mem_leaks(IntPtr bio);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_mem_leaks_cb(CryptoUtil.MemoryLeakHandler cb);

		#endregion

		#region OBJ
		public const int NID_undef = 0;

		public const int OBJ_undef = 0;

		public const int OBJ_NAME_TYPE_UNDEF = 0x00;
		public const int OBJ_NAME_TYPE_MD_METH = 0x01;
		public const int OBJ_NAME_TYPE_CIPHER_METH = 0x02;
		public const int OBJ_NAME_TYPE_PKEY_METH = 0x03;
		public const int OBJ_NAME_TYPE_COMP_METH = 0x04;
		public const int OBJ_NAME_TYPE_NUM = 0x05;

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void OBJ_NAME_do_all(int type, ObjectNameHandler fn, IntPtr arg);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void OBJ_NAME_do_all_sorted(int type, ObjectNameHandler fn, IntPtr arg);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int OBJ_txt2nid(string s);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr OBJ_nid2obj(int n);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string OBJ_nid2ln(int n);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string OBJ_nid2sn(int n);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int OBJ_obj2nid(IntPtr o);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr OBJ_txt2obj(string s, int no_name);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int OBJ_ln2nid(string s);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int OBJ_sn2nid(string s);
		#endregion

		#region stack
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr sk_new_null();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int sk_num(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int sk_find(IntPtr stack, IntPtr data);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int sk_insert(IntPtr stack, IntPtr data, int where);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr sk_shift(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int sk_unshift(IntPtr stack, IntPtr data);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int sk_push(IntPtr stack, IntPtr data);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr sk_pop(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr sk_delete(IntPtr stack, int loc);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr sk_delete_ptr(IntPtr stack, IntPtr p);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr sk_value(IntPtr stack, int index);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr sk_set(IntPtr stack, int index, IntPtr data);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr sk_dup(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void sk_zero(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void sk_free(IntPtr stack);

		#endregion

		#region SHA
		public const int SHA_DIGEST_LENGTH = 20;
		#endregion

		#region ASN1
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ASN1_INTEGER_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ASN1_INTEGER_free(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ASN1_INTEGER_set(IntPtr a, int v);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ASN1_INTEGER_get(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ASN1_TIME_set(IntPtr s, long t);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ASN1_UTCTIME_print(IntPtr bp, IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ASN1_TIME_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ASN1_TIME_free(IntPtr x);

		public const int V_ASN1_OCTET_STRING = 4;

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ASN1_STRING_type_new(int type);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ASN1_STRING_dup(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ASN1_STRING_free(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ASN1_STRING_cmp(IntPtr a, IntPtr b);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ASN1_STRING_set(IntPtr str, byte[] data, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ASN1_STRING_data(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ASN1_STRING_length(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ASN1_OBJECT_free(IntPtr obj);

		#endregion

		#region X509_REQ
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_REQ_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_REQ_set_version(IntPtr x, int version);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_REQ_set_pubkey(IntPtr x, IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_REQ_get_pubkey(IntPtr req);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_REQ_set_subject_name(IntPtr x, IntPtr name);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_REQ_sign(IntPtr x, IntPtr pkey, IntPtr md);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_REQ_verify(IntPtr x, IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_REQ_digest(IntPtr data, IntPtr type, byte[] md, ref uint len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_REQ_free(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_REQ_to_X509(IntPtr r, int days, IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_REQ_print_ex(IntPtr bp, IntPtr x, uint nmflag, uint cflag);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_REQ_print(IntPtr bp, IntPtr x);
		#endregion

		#region X509
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_dup(IntPtr x509);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_cmp(IntPtr a, IntPtr b);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_sign(IntPtr x, IntPtr pkey, IntPtr md);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_check_private_key(IntPtr x509, IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_verify(IntPtr x, IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_pubkey_digest(IntPtr data, IntPtr type, byte[] md, ref uint len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_digest(IntPtr data, IntPtr type, byte[] md, ref uint len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_set_version(IntPtr x, int version);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_set_serialNumber(IntPtr x, IntPtr serial);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_get_serialNumber(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_set_issuer_name(IntPtr x, IntPtr name);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_get_issuer_name(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_set_subject_name(IntPtr x, IntPtr name);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_get_subject_name(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_set_notBefore(IntPtr x, IntPtr tm);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_set_notAfter(IntPtr x, IntPtr tm);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_set_pubkey(IntPtr x, IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_get_pubkey(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_free(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_verify_cert(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_verify_cert_error_string(int n);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_to_X509_REQ(IntPtr x, IntPtr pkey, IntPtr md);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_print_ex(IntPtr bp, IntPtr x, uint nmflag, uint cflag);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_print(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_find_by_issuer_and_serial(IntPtr sk, IntPtr name, IntPtr serial);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_find_by_subject(IntPtr sk, IntPtr name);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_check_trust(IntPtr x, int id, int flags);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_time_adj(IntPtr s, int adj, ref long t);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_gmtime_adj(IntPtr s, int adj);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr d2i_X509_bio(IntPtr bp, ref IntPtr x509);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int i2d_X509_bio(IntPtr bp, IntPtr x509);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_PUBKEY_free(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_OBJECT_up_ref_count(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_OBJECT_free_contents(IntPtr a);

		#endregion

		#region X509_EXTENSION
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_EXTENSION_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_EXTENSION_free(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_EXTENSION_dup(IntPtr ex);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509V3_EXT_print(IntPtr bio, IntPtr ext, uint flag, int indent);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509V3_EXT_get_nid(int nid);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_add_ext(IntPtr x, IntPtr ex, int loc);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_add1_ext_i2d(IntPtr x, int nid, byte[] value, int crit, uint flags);

		//X509_EXTENSION* X509V3_EXT_conf_nid(LHASH* conf, X509V3_CTX* ctx, int ext_nid, char* value);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509V3_EXT_conf_nid(IntPtr conf, IntPtr ctx, int ext_nid, string value);

		//X509_EXTENSION* X509_EXTENSION_create_by_NID(X509_EXTENSION** ex, int nid, int crit, ASN1_OCTET_STRING* data);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_EXTENSION_create_by_NID(IntPtr ex, int nid, int crit, IntPtr data);

		//X509_EXTENSION* X509_EXTENSION_create_by_OBJ(X509_EXTENSION** ex, ASN1_OBJECT* obj, int crit, ASN1_OCTET_STRING* data);
		//int X509_EXTENSION_set_object(X509_EXTENSION* ex, ASN1_OBJECT* obj);
		//int X509_EXTENSION_set_critical(X509_EXTENSION* ex, int crit);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_EXTENSION_set_critical(IntPtr ex, int crit);

		//int X509_EXTENSION_set_data(X509_EXTENSION* ex, ASN1_OCTET_STRING* data);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_EXTENSION_set_data(IntPtr ex, IntPtr data);

		//ASN1_OBJECT* X509_EXTENSION_get_object(X509_EXTENSION* ex);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_EXTENSION_get_object(IntPtr ex);

		//ASN1_OCTET_STRING* X509_EXTENSION_get_data(X509_EXTENSION* ne);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_EXTENSION_get_data(IntPtr ne);

		//int X509_EXTENSION_get_critical(X509_EXTENSION* ex);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_EXTENSION_get_critical(IntPtr ex);

		#endregion

		#region X509_STORE
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_STORE_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_STORE_add_cert(IntPtr ctx, IntPtr x);

		//[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		//void X509_STORE_set_flags();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_STORE_free(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_STORE_CTX_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_STORE_CTX_init(IntPtr ctx, IntPtr store, IntPtr x509, IntPtr chain);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_STORE_CTX_free(IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_STORE_CTX_get_current_cert(IntPtr x509_store_ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_STORE_CTX_get_error_depth(IntPtr x509_store_ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_STORE_CTX_get_error(IntPtr x509_store_ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_STORE_CTX_set_error(IntPtr x509_store_ctx, int error);

		#endregion

		#region X509_INFO
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_INFO_free(IntPtr a);
		#endregion

		#region X509_NAME
		public const int MBSTRING_FLAG = 0x1000;

		public const int MBSTRING_ASC = MBSTRING_FLAG | 1;

		public const int ASN1_STRFLGS_RFC2253 =
			ASN1_STRFLGS_ESC_2253 |
			ASN1_STRFLGS_ESC_CTRL |
			ASN1_STRFLGS_ESC_MSB |
			ASN1_STRFLGS_UTF8_CONVERT |
			ASN1_STRFLGS_DUMP_UNKNOWN |
			ASN1_STRFLGS_DUMP_DER;

		public const int ASN1_STRFLGS_ESC_2253 = 1;
		public const int ASN1_STRFLGS_ESC_CTRL = 2;
		public const int ASN1_STRFLGS_ESC_MSB = 4;
		public const int ASN1_STRFLGS_ESC_QUOTE = 8;
		public const int ASN1_STRFLGS_UTF8_CONVERT = 0x10;
		public const int ASN1_STRFLGS_DUMP_UNKNOWN = 0x100;
		public const int ASN1_STRFLGS_DUMP_DER = 0x200;
		public const int XN_FLAG_SEP_COMMA_PLUS = (1 << 16);
		public const int XN_FLAG_FN_SN = 0;

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_NAME_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509_NAME_free(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_NAME_dup(IntPtr xn);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_cmp(IntPtr a, IntPtr b);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_entry_count(IntPtr name);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_add_entry_by_NID(IntPtr name, int nid, int type, byte[] bytes, int len, int loc, int set);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_add_entry_by_txt(IntPtr name, byte[] field, int type, byte[] bytes, int len, int loc, int set);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_get_text_by_NID(IntPtr name, int nid, byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_NAME_get_entry(IntPtr name, int loc);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_NAME_delete_entry(IntPtr name, int loc);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_get_index_by_NID(IntPtr name, int nid, int lastpos);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_digest(IntPtr data, IntPtr type, byte[] md, ref uint len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr X509_NAME_oneline(IntPtr a, byte[] buf, int size);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_print(IntPtr bp, IntPtr name, int obase);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509_NAME_print_ex(IntPtr bp, IntPtr nm, int indent, uint flags);
		#endregion

		#region RAND
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_set_rand_method(IntPtr meth);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr RAND_get_rand_method();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void RAND_cleanup();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void RAND_seed(byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_pseudo_bytes(byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_bytes(byte[] buf, int num);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void RAND_add(byte[] buf, int num, double entropy);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_load_file(string file, int max_bytes);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_write_file(string file);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string RAND_file_name(byte[] buf, uint num);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_status();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_query_egd_bytes(string path, byte[] buf, int bytes);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_egd(string path);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_egd_bytes(string path, int bytes);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RAND_poll();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_rand(IntPtr rnd, int bits, int top, int bottom);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_pseudo_rand(IntPtr rnd, int bits, int top, int bottom);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_rand_range(IntPtr rnd, IntPtr range);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_pseudo_rand_range(IntPtr rnd, IntPtr range);
		#endregion

		#region DSA
		//[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		//public extern static IntPtr DSA_generate_parameters(int bits, byte[] seed, int seed_len, IntPtr counter_ret, IntPtr h_ret, IntPtr callback, IntPtr cb_arg);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static
		int DSA_generate_parameters_ex(IntPtr dsa,
		                               int bits,
		                               byte[] seed,
		                               int seed_len,
		                               out int counter_ret,
		                               out IntPtr h_ret,
		                               bn_gencb_st callback);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DSA_generate_key(IntPtr dsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr DSA_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void DSA_free(IntPtr dsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DSA_size(IntPtr dsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DSAparams_print(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DSA_print(IntPtr bp, IntPtr x, int off);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DSA_sign(int type, byte[] dgst, int dlen, byte[] sig, out uint siglen, IntPtr dsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DSA_verify(int type, byte[] dgst, int dgst_len, byte[] sigbuf, int siglen, IntPtr dsa);
		#endregion

		#region RSA
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr RSA_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void RSA_free(IntPtr rsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_size(IntPtr rsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_generate_key_ex(IntPtr rsa, int bits, IntPtr e, bn_gencb_st cb);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_check_key(IntPtr rsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_public_encrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_private_encrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_public_decrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_private_decrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_sign(int type, byte[] m, uint m_length, byte[] sigret, out uint siglen, IntPtr rsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_verify(int type, byte[] m, uint m_length, byte[] sigbuf, uint siglen, IntPtr rsa);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int RSA_print(IntPtr bp, IntPtr r, int offset);
		#endregion

		#region DH
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr DH_generate_parameters(int prime_len, int generator, IntPtr callback, IntPtr cb_arg);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DH_generate_parameters_ex(IntPtr dh, int prime_len, int generator, bn_gencb_st cb);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DH_generate_key(IntPtr dh);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DH_compute_key(byte[] key, IntPtr pub_key, IntPtr dh);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr DH_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void DH_free(IntPtr dh);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DH_check(IntPtr dh, out int codes);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DHparams_print(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int DH_size(IntPtr dh);

		#endregion

		#region BIGNUM
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_value_one();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_CTX_new();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_CTX_init(IntPtr c);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_CTX_free(IntPtr c);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_CTX_start(IntPtr ctx);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_CTX_get(IntPtr ctx);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_CTX_end(IntPtr ctx);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_new();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_free(IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_init(IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_bin2bn(byte[] s, int len, IntPtr ret);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_bn2bin(IntPtr a, byte[] to);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_clear_free(IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_clear(IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_dup(IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_copy(IntPtr a, IntPtr b);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BN_swap(IntPtr a, IntPtr b);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_cmp(IntPtr a, IntPtr b);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_sub(IntPtr r, IntPtr a, IntPtr b);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_add(IntPtr r, IntPtr a, IntPtr b);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_mul(IntPtr r, IntPtr a, IntPtr b, IntPtr ctx);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_num_bits(IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_sqr(IntPtr r, IntPtr a, IntPtr ctx);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_div(IntPtr dv, IntPtr rem, IntPtr m, IntPtr d, IntPtr ctx);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_print(IntPtr fp, IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_bn2hex(IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BN_bn2dec(IntPtr a);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_hex2bn(out IntPtr a, byte[] str);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_dec2bn(out IntPtr a, byte[] str);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint BN_mod_word(IntPtr a, uint w);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint BN_div_word(IntPtr a, uint w);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_mul_word(IntPtr a, uint w);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_add_word(IntPtr a, uint w);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_sub_word(IntPtr a, uint w);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BN_set_word(IntPtr a, uint w);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint BN_get_word(IntPtr a);
		//#define BN_GENCB_set(gencb, callback, cb_arg) { \
		//        BN_GENCB *tmp_gencb = (gencb); \
		//        tmp_gencb->ver = 2; \
		//        tmp_gencb->arg = (cb_arg); \
		//        tmp_gencb->cb.cb_2 = (callback); }

		[StructLayout(LayoutKind.Sequential)]
		public class bn_gencb_st
		{
			public uint ver; /// To handle binary (in)compatibility 
			public IntPtr arg; /// callback-specific data 
			public GeneratorHandler cb;
		}
		#endregion

		#region DER
		//#define d2i_DHparams_bio(bp,x) ASN1_d2i_bio_of(DH,DH_new,d2i_DHparams,bp,x)
		//#define i2d_DHparams_bio(bp,x) ASN1_i2d_bio_of_const(DH,i2d_DHparams,bp,x)
		//
		//#define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
		//    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
		//              CHECKED_D2I_OF(type, d2i), \
		//              in, \
		//              CHECKED_PPTR_OF(type, x)))
		//
		//#define ASN1_i2d_bio_of_const(type,i2d,out,x) \
		//    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
		//          out, \
		//          CHECKED_PTR_OF(const type, x)))
		//
		//#define CHECKED_I2D_OF(type, i2d) \
		//    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
		//
		//#define I2D_OF(type) int (*)(type *,byte[] *)
		//
		//#define CHECKED_PTR_OF(type, p) \
		//    ((void*) (1 ? p : (type*)0))

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public static extern IntPtr d2i_DHparams(out IntPtr a, IntPtr pp, int length);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int i2d_DHparams(IntPtr a, IntPtr pp);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ASN1_d2i_bio(IntPtr xnew, IntPtr d2i, IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ASN1_i2d_bio(IntPtr i2d, IntPtr bp, IntPtr x);
		#endregion

		#region PEM

		#region X509
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_X509(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_X509(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_PKCS7(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr d2i_PKCS7_bio(IntPtr bp, IntPtr p7);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void PKCS7_free(IntPtr p7);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr d2i_PKCS12_bio(IntPtr bp, IntPtr p12);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int i2d_PKCS12_bio(IntPtr bp, IntPtr p12);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		//PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype);
		public extern static IntPtr PKCS12_create(string pass, string name, IntPtr pkey, IntPtr cert, IntPtr ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		//int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
		public extern static int PKCS12_parse(IntPtr p12, string pass, out IntPtr pkey, out IntPtr cert, out IntPtr ca);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void PKCS12_free(IntPtr p12);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		//!!int PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u);
		public extern static int PEM_write_bio_PKCS8PrivateKey(IntPtr bp, IntPtr evp_pkey, IntPtr evp_cipher, IntPtr kstr, int klen, pem_password_cb cb, IntPtr user_data);

		#endregion

		#region X509_INFO
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_X509_INFO(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_X509_INFO(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region X509_AUX
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_X509_AUX(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_X509_AUX(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region X509_REQ
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_X509_REQ(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_X509_REQ(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region X509_REQ_NEW
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_X509_REQ_NEW(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_X509_REQ_NEW(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region X509_CRL
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_X509_CRL(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_X509_CRL(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region X509Chain
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_X509_INFO_read_bio(IntPtr bp, IntPtr sk, pem_password_cb cb, IntPtr u);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_X509_INFO_write_bio(IntPtr bp, IntPtr xi, IntPtr enc, byte[] kstr, int klen, IntPtr cd, IntPtr u);
		#endregion

		#region DSA
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_DSAPrivateKey(IntPtr bp, IntPtr x, IntPtr enc, byte[] kstr, int klen, pem_password_cb cb, IntPtr u);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_DSAPrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_DSA_PUBKEY(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_DSA_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region DSAparams
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_DSAparams(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_DSAparams(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region RSA
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_RSA_PUBKEY(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_RSA_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_RSAPrivateKey(IntPtr bp, IntPtr x, IntPtr enc, byte[] kstr, int klen, pem_password_cb cb, IntPtr u);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_RSAPrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region DHparams
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_DHparams(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_DHparams(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region PrivateKey
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_PrivateKey(IntPtr bp, IntPtr x, IntPtr enc, byte[] kstr, int klen, pem_password_cb cb, IntPtr u);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_PrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#region PUBKEY
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int PEM_write_bio_PUBKEY(IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr PEM_read_bio_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);
		#endregion

		#endregion

		#region EVP

		#region Constants
		public const int EVP_MAX_MD_SIZE = 64; //!!(16+20);
		public const int EVP_MAX_KEY_LENGTH = 32;
		public const int EVP_MAX_IV_LENGTH = 16;
		public const int EVP_MAX_BLOCK_LENGTH = 32;

		public const int EVP_CIPH_STREAM_CIPHER = 0x0;
		public const int EVP_CIPH_ECB_MODE = 0x1;
		public const int EVP_CIPH_CBC_MODE = 0x2;
		public const int EVP_CIPH_CFB_MODE = 0x3;
		public const int EVP_CIPH_OFB_MODE = 0x4;
		public const int EVP_CIPH_MODE = 0x7;
		public const int EVP_CIPH_VARIABLE_LENGTH = 0x8;
		public const int EVP_CIPH_CUSTOM_IV = 0x10;
		public const int EVP_CIPH_ALWAYS_CALL_INIT = 0x20;
		public const int EVP_CIPH_CTRL_INIT = 0x40;
		public const int EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80;
		public const int EVP_CIPH_NO_PADDING = 0x100;
		public const int EVP_CIPH_FLAG_FIPS = 0x400;
		public const int EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x800;
		#endregion

		#region Message Digests
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_md_null();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_md2();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_md4();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_md5();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha1();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha224();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha256();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha384();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha512();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_dss();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_dss1();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_mdc2();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_ripemd160();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_ecdsa();
		#endregion

		#region HMAC
		public const int HMAC_MAX_MD_CBLOCK = 128;

		//!!void HMAC_CTX_init(HMAC_CTX *ctx);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void HMAC_CTX_init(IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void HMAC_CTX_set_flags(IntPtr ctx, uint flags);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void HMAC_CTX_cleanup(IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void HMAC_Init(IntPtr ctx, byte[] key, int len, IntPtr md); /* deprecated */
		
		//!!public extern static void HMAC_Init_ex(IntPtr ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void HMAC_Init_ex(IntPtr ctx, byte[] key, int len, IntPtr md, IntPtr engine_impl);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void HMAC_Update(IntPtr ctx, byte[] data, int len);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void HMAC_Final(IntPtr ctx, byte[] md, ref uint len);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr HMAC(IntPtr evp_md, byte[] key, int key_len, byte[] d, int n, byte[] md, ref uint md_len);
		#endregion

		#region Ciphers
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_get_cipherbyname(byte[] name);
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_enc_null();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_cfb64();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_cfb1();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_cfb8();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede_cfb64();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_cfb64();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_cfb1();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_cfb8();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_desx_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc4();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc4_40();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_idea_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_idea_cfb64();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_idea_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_idea_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_40_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_64_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_cfb64();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_bf_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_bf_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_bf_cfb64();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_bf_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_cast5_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_cast5_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_cast5_cfb64();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_cast5_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc5_32_12_16_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc5_32_12_16_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc5_32_12_16_cfb64();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc5_32_12_16_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_cfb1();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_cfb8();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_cfb128();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_cfb1();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_cfb8();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_cfb128();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_ofb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_ecb();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_cbc();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_cfb1();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_cfb8();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_cfb128();
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_ofb();

		#endregion

		#region EVP_PKEY
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EVP_PKEY_free(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_cmp(IntPtr a, IntPtr b);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_decrypt(byte[] dec_key, byte[] enc_key, int enc_key_len, IntPtr private_key);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_encrypt(byte[] enc_key, byte[] key, int key_len, IntPtr pub_key);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_type(int type);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_bits(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_size(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_assign(IntPtr pkey, int type, byte[] key);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_set1_DSA(IntPtr pkey, IntPtr key);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_get1_DSA(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_set1_RSA(IntPtr pkey, IntPtr key);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_get1_RSA(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_set1_DH(IntPtr pkey, IntPtr key);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_get1_DH(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_copy_parameters(IntPtr to, IntPtr from);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_missing_parameters(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_save_parameters(IntPtr pkey, int mode);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_cmp_parameters(IntPtr a, IntPtr b);

		#endregion

		#region EVP_CIPHER
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EVP_CIPHER_CTX_init(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_set_padding(IntPtr x, int padding);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_set_key_length(IntPtr x, int keylen);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_ctrl(IntPtr ctx, int type, int arg, IntPtr ptr);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_cleanup(IntPtr a);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_type(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_CipherInit_ex(IntPtr ctx, IntPtr type, IntPtr impl, byte[] key, byte[] iv, int enc);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_CipherUpdate(IntPtr ctx, byte[] outb, out int outl, byte[] inb, int inl);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_CipherFinal_ex(IntPtr ctx, byte[] outm, ref int outl);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_OpenInit(IntPtr ctx, IntPtr type, byte[] ek, int ekl, byte[] iv, IntPtr priv);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_OpenFinal(IntPtr ctx, byte[] outb, out int outl);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_SealInit(IntPtr ctx, IntPtr type, byte[][] ek, int[] ekl, byte[] iv, IntPtr[] pubk, int npubk);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_SealFinal(IntPtr ctx, byte[] outb, out int outl);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_DecryptUpdate(IntPtr ctx, byte[] output, out int outl, byte[] input, int inl);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_EncryptUpdate(IntPtr ctx, byte[] output, out int outl, byte[] input, int inl);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_BytesToKey(IntPtr type, IntPtr md, byte[] salt, byte[] data, int datal, int count, byte[] key, byte[] iv);

		#endregion

		#region EVP_MD
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_get_digestbyname(byte[] name);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EVP_MD_CTX_init(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_MD_CTX_cleanup(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EVP_MD_CTX_create();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EVP_MD_CTX_destroy(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_DigestInit_ex(IntPtr ctx, IntPtr type, IntPtr impl);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_DigestUpdate(IntPtr ctx, byte[] d, uint cnt);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_DigestFinal_ex(IntPtr ctx, byte[] md, ref uint s);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_Digest(byte[] data, uint count, byte[] md, ref uint size, IntPtr type, IntPtr impl);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_SignFinal(IntPtr ctx, byte[] md, ref uint s, IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EVP_VerifyFinal(IntPtr ctx, byte[] sigbuf, uint siglen, IntPtr pkey);

		#endregion

		#endregion
		
		#region EC
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_get_builtin_curves(IntPtr r, int nitems);
		
		#region EC_METHOD
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GFp_simple_method();
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GFp_mont_method();
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GFp_nist_method();
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GF2m_simple_method();
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_METHOD_get_field_type(IntPtr meth);
		#endregion
		
		#region EC_GROUP
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GROUP_new(IntPtr meth);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_GROUP_free(IntPtr group);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_GROUP_clear_free(IntPtr group);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_copy(IntPtr dst, IntPtr src);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GROUP_dup(IntPtr src);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GROUP_method_of(IntPtr group);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_set_generator(IntPtr group, IntPtr generator, IntPtr order, IntPtr cofactor);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GROUP_get0_generator(IntPtr group);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_order(IntPtr group, IntPtr order, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_cofactor(IntPtr group, IntPtr cofactor, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_GROUP_set_curve_name(IntPtr group, int nid);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_curve_name(IntPtr group);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_GROUP_set_asn1_flag(IntPtr group, int flag);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_asn1_flag(IntPtr group);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_GROUP_set_point_conversion_form(IntPtr x, int y);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_point_conversion_form(IntPtr x);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static byte[] EC_GROUP_get0_seed(IntPtr x);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_seed_len(IntPtr x);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_set_seed(IntPtr x, byte[] buf, int len);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_set_curve_GFp(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_curve_GFp(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_set_curve_GF2m(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_curve_GF2m(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_get_degree(IntPtr group);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_check(IntPtr group, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_check_discriminant(IntPtr group, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_cmp(IntPtr a, IntPtr b, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GROUP_new_curve_GFp(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GROUP_new_curve_GF2m(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_GROUP_new_by_curve_name(int nid);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_precompute_mult(IntPtr group, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_GROUP_have_precompute_mult(IntPtr group);
		#endregion

		#region EC_POINT
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_POINT_new(IntPtr group);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_POINT_free(IntPtr point);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_POINT_clear_free(IntPtr point);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_copy(IntPtr dst, IntPtr src);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_POINT_dup(IntPtr src, IntPtr group);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_POINT_method_of(IntPtr point);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_set_to_infinity(IntPtr group, IntPtr point);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_set_Jprojective_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr z, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_get_Jprojective_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr z, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_set_affine_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_get_affine_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_set_compressed_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, int y_bit, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_set_affine_coordinates_GF2m(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_get_affine_coordinates_GF2m(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_set_compressed_coordinates_GF2m(IntPtr group, IntPtr p, IntPtr x, int y_bit, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_point2oct(IntPtr group, IntPtr p, int form, byte[] buf, int len, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_oct2point(IntPtr group, IntPtr p, byte[] buf, int len, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_POINT_point2bn(IntPtr a, IntPtr b, int form, IntPtr c, IntPtr d);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_POINT_bn2point(IntPtr a, IntPtr b, IntPtr c, IntPtr d);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string EC_POINT_point2hex(IntPtr a, IntPtr b, int form, IntPtr c);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_POINT_hex2point(IntPtr a, string s, IntPtr b, IntPtr c);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_add(IntPtr group, IntPtr r, IntPtr a, IntPtr b, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_dbl(IntPtr group, IntPtr r, IntPtr a, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_invert(IntPtr group, IntPtr a, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_is_at_infinity(IntPtr group, IntPtr p);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_is_on_curve(IntPtr group, IntPtr point, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_cmp(IntPtr group, IntPtr a, IntPtr b, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_make_affine(IntPtr a, IntPtr b, IntPtr c);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINTs_make_affine(IntPtr a, int num, IntPtr[] b, IntPtr c);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINTs_mul(IntPtr group, IntPtr r, IntPtr n, int num, IntPtr[] p, IntPtr[] m, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_POINT_mul(IntPtr group, IntPtr r, IntPtr n, IntPtr q, IntPtr m, IntPtr ctx);
		#endregion
		
		#region EC_KEY
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr EC_KEY_dup_func(IntPtr x);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void EC_KEY_free_func(IntPtr x);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_KEY_new();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_KEY_new_by_curve_name(int nid);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_KEY_free(IntPtr key);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_KEY_copy(IntPtr dst, IntPtr src);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_KEY_dup(IntPtr src);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_KEY_up_ref(IntPtr key);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_KEY_get0_group(IntPtr key);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_KEY_set_group(IntPtr key, IntPtr group);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_KEY_get0_private_key(IntPtr key);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_KEY_set_private_key(IntPtr key, IntPtr prv);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_KEY_get0_public_key(IntPtr key);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_KEY_set_public_key(IntPtr key, IntPtr pub);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint EC_KEY_get_enc_flags(IntPtr key);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_KEY_set_enc_flags(IntPtr x, uint y);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_KEY_get_conv_form(IntPtr x);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_KEY_set_conv_form(IntPtr x, int y);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr EC_KEY_get_key_method_data(IntPtr x, EC_KEY_dup_func dup_func, EC_KEY_free_func free_func, EC_KEY_free_func clear_free_func);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_KEY_insert_key_method_data(IntPtr x, IntPtr data, EC_KEY_dup_func dup_func, EC_KEY_free_func free_func, EC_KEY_free_func clear_free_func);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void EC_KEY_set_asn1_flag(IntPtr x, int y);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_KEY_precompute_mult(IntPtr key, IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_KEY_generate_key(IntPtr key);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int EC_KEY_check_key(IntPtr key);
		#endregion
		
		#region ECDSA
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDSA_SIG_new();
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ECDSA_SIG_free(IntPtr sig);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int i2d_ECDSA_SIG(IntPtr sig, byte[] pp);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr d2i_ECDSA_SIG(IntPtr sig, byte[] pp, long len);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDSA_do_sign(byte[] dgst, int dgst_len, IntPtr eckey);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDSA_do_sign_ex(byte[] dgst, int dgstlen, IntPtr kinv, IntPtr rp, IntPtr eckey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_do_verify(byte[] dgst, int dgst_len, IntPtr sig, IntPtr eckey);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDSA_OpenSSL();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ECDSA_set_default_method(IntPtr meth);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDSA_get_default_method();
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_set_method(IntPtr eckey, IntPtr meth);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_size(IntPtr eckey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_sign_setup(IntPtr eckey, IntPtr ctx, IntPtr kinv, IntPtr rp);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_sign(int type, byte[] dgst, int dgstlen, byte[] sig, ref uint siglen, IntPtr eckey);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_sign_ex(int type, byte[] dgst, int dgstlen, byte[] sig, ref uint siglen, IntPtr kinv, IntPtr rp, IntPtr eckey);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_verify(int type, byte[] dgst, int dgstlen, byte[] sig, int siglen, IntPtr eckey);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_get_ex_new_index(IntPtr argl, IntPtr argp, IntPtr new_func, IntPtr dup_func, IntPtr free_func);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDSA_set_ex_data(IntPtr d, int idx, IntPtr arg);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDSA_get_ex_data(IntPtr d, int idx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_load_ECDSA_strings();
		#endregion
		
		#region ECDH
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDH_OpenSSL();
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ECDH_set_default_method(IntPtr method);
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDH_get_default_method();
		
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDH_set_method(IntPtr key, IntPtr method);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr ECDH_KDF([MarshalAs(UnmanagedType.LPArray, SizeParamIndex=1)] byte[] pin,
		                                int inlen,
		                                IntPtr pout, 
		                                ref int outlen);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDH_compute_key(byte[] pout, int outlen, IntPtr pub_key, IntPtr ecdh, ECDH_KDF kdf);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDH_get_ex_new_index(IntPtr argl, IntPtr argp, IntPtr new_func, IntPtr dup_func, IntPtr free_func);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int ECDH_set_ex_data(IntPtr d, int idx, IntPtr arg);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ECDH_get_ex_data(IntPtr d, int idx);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_load_ECDH_strings();
		#endregion

		#endregion

		#region BIO
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		//!!public extern static IntPtr BIO_new_file(byte[] filename, byte[] mode);
		public extern static IntPtr BIO_new_file(string filename, string mode);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BIO_new_mem_buf(byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BIO_s_mem();

		// Unsupported!
		//[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		//public extern static IntPtr BIO_s_fd();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BIO_f_md();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BIO_f_null();

		const int BIO_C_SET_FD = 104;
		const int BIO_C_SET_MD = 111;
		const int BIO_C_GET_MD = 112;
		const int BIO_C_GET_MD_CTX = 120;
		const int BIO_C_SET_MD_CTX = 148;

		public const int BIO_NOCLOSE = 0x00;
		public const int BIO_CLOSE = 0x01;

		public static void BIO_set_md(IntPtr bp, IntPtr md)
		{
			Native.ExpectSuccess(BIO_ctrl(bp, BIO_C_SET_MD, 0, md));
		}

		// Unsupported!
		//public static void BIO_set_fd(IntPtr bp, int fd, int c)
		//{
		//    Native.ExpectSuccess(BIO_int_ctrl(bp, BIO_C_SET_FD, c, fd));
		//}

		public static IntPtr BIO_get_md(IntPtr bp)
		{
			IntPtr ptr = Marshal.AllocHGlobal(4);
			try
			{
				ExpectSuccess(BIO_ctrl(bp, BIO_C_GET_MD, 0, ptr));
				return Marshal.ReadIntPtr(ptr);
			}
			finally
			{
				Marshal.FreeHGlobal(ptr);
			}
		}

		public static IntPtr BIO_get_md_ctx(IntPtr bp)
		{
			IntPtr ptr = Marshal.AllocHGlobal(4);
			try
			{
				ExpectSuccess(BIO_ctrl(bp, BIO_C_GET_MD_CTX, 0, ptr));
				return Marshal.ReadIntPtr(ptr);
			}
			finally
			{
				Marshal.FreeHGlobal(ptr);
			}
		}

		public static void BIO_set_md_ctx(IntPtr bp, IntPtr mdcp)
		{
			Native.ExpectSuccess(BIO_ctrl(bp, BIO_C_SET_MD_CTX, 0, mdcp));
		}

		const int BIO_CTRL_SET_CLOSE = 9;  /* man - set the 'close' on free */

		//#define BIO_set_close(b,c)	(int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)
		public static int BIO_set_close(IntPtr bp, int arg)
		{
			return BIO_ctrl(bp, BIO_CTRL_SET_CLOSE, arg, IntPtr.Zero);
		}

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BIO_push(IntPtr bp, IntPtr append);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BIO_ctrl(IntPtr bp, int cmd, int larg, IntPtr parg);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BIO_int_ctrl(IntPtr bp, int cmd, int larg, int parg);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr BIO_new(IntPtr type);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BIO_read(IntPtr b, byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BIO_write(IntPtr b, byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BIO_puts(IntPtr b, byte[] buf);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int BIO_gets(IntPtr b, byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void BIO_free(IntPtr bio);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint BIO_number_read(IntPtr bio);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint BIO_number_written(IntPtr bio);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint BIO_ctrl_pending(IntPtr bio);

		#endregion

		#region ERR
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_load_crypto_strings();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static uint ERR_get_error();

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_error_string_n(uint e, byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ERR_lib_error_string(uint e);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ERR_func_error_string(uint e);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr ERR_reason_error_string(uint e);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_remove_state(uint pid);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_clear_error();

		#endregion

		#region NCONF

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr NCONF_new(IntPtr meth);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void NCONF_free(IntPtr conf);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		//!!public extern static int NCONF_load(IntPtr conf, byte[] file, ref int eline);
		public extern static int NCONF_load(IntPtr conf, string file, ref int eline);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr NCONF_get_string(IntPtr conf, byte[] group, byte[] name);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509V3_set_ctx(IntPtr ctx, IntPtr issuer, IntPtr subject, IntPtr req, IntPtr crl, int flags);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void X509V3_set_nconf(IntPtr ctx, IntPtr conf);

		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int X509V3_EXT_add_nconf(IntPtr conf, IntPtr ctx, byte[] section, IntPtr cert);

		#endregion

		#region FIPS
		[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int FIPS_mode_set(int onoff);

		#endregion

		#region SSL Routines
		#region Initialization
		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_load_error_strings();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_library_init();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_free_strings();

		#endregion

		#region SSL Methods

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv2_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv2_server_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv2_client_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv3_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv3_server_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv3_client_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv23_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv23_server_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSLv23_client_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr TLSv1_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr TLSv1_client_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr TLSv1_server_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr DTLSv1_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr DTLSv1_client_method();

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr DTLSv1_server_method();

		#endregion

		#region SSL_CTX
		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_CTX_new(IntPtr sslMethod);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_CTX_free(IntPtr ctx);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_ctrl(IntPtr ctx, int cmd, int arg, IntPtr parg);

		public const int SSL_CTRL_OPTIONS = 32;
		public const int SSL_CTRL_MODE = 33;

		public const int SSL_OP_MICROSOFT_SESS_ID_BUG = 0x00000001;
		public const int SSL_OP_NETSCAPE_CHALLENGE_BUG = 0x00000002;
		public const int SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000008;
		public const int SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x00000010;
		public const int SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 0x00000020;
		public const int SSL_OP_MSIE_SSLV2_RSA_PADDING = 0x00000040; /* no effect since 0.9.7h and 0.9.8b */
		public const int SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 0x00000080;
		public const int SSL_OP_TLS_D5_BUG = 0x00000100;
		public const int SSL_OP_TLS_BLOCK_PADDING_BUG = 0x00000200;

		/* Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added
		 * in OpenSSL 0.9.6d.  Usually (depending on the application protocol)
		 * the workaround is not needed.  Unfortunately some broken SSL/TLS
		 * implementations cannot handle it at all, which is why we include
		 * it in SSL_OP_ALL. */
		public const int SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800; /* added in 0.9.6e */

		/* SSL_OP_ALL: various bug workarounds that should be rather harmless.
		 *             This used to be 0x000FFFFFL before 0.9.7. */
		public const int SSL_OP_ALL = (0x00000FFF ^ SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG);

		/* As server, disallow session resumption on renegotiation */
		public const int SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000;
		/* If set, always create a new key when using tmp_dh parameters */
		public const int SSL_OP_SINGLE_DH_USE = 0x00100000;
		/* Set to always use the tmp_rsa key when doing RSA operations,
		 * even when this violates protocol specs */
		public const int SSL_OP_EPHEMERAL_RSA = 0x00200000;
		/* Set on servers to choose the cipher according to the server's
		 * preferences */
		public const int SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000;
		/* If set, a server will allow a client to issue a SSLv3.0 version number
		 * as latest version supported in the premaster secret, even when TLSv1.0
		 * (version 3.1) was announced in the client hello. Normally this is
		 * forbidden to prevent version rollback attacks. */
		public const int SSL_OP_TLS_ROLLBACK_BUG = 0x00800000;

		public const int SSL_OP_NO_SSLv2 = 0x01000000;
		public const int SSL_OP_NO_SSLv3 = 0x02000000;
		public const int SSL_OP_NO_TLSv1 = 0x04000000;

		/* The next flag deliberately changes the ciphertest, this is a check
		 * for the PKCS#1 attack */
		public const int SSL_OP_PKCS1_CHECK_1 = 0x08000000;
		public const int SSL_OP_PKCS1_CHECK_2 = 0x10000000;
		public const int SSL_OP_NETSCAPE_CA_DN_BUG = 0x20000000;
		public const int SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x40000000;


		/* Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
		 * when just a single record has been written): */
		public const int SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001;
		/* Make it possible to retry SSL_write() with changed buffer location
		 * (buffer contents must stay the same!); this is not the default to avoid
		 * the misconception that non-blocking SSL_write() behaves like
		 * non-blocking write(): */
		public const int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002;
		/* Never bother the application with retries if the transport
		 * is blocking: */
		public const int SSL_MODE_AUTO_RETRY = 0x00000004;
		/* Don't attempt to automatically build certificate chain */
		public const int SSL_MODE_NO_AUTO_CHAIN = 0x00000008;

		/// <summary>
		/// #define SSL_CTX_ctrl in ssl.h - calls SSL_CTX_ctrl()
		/// </summary>
		/// <param name="ctx"></param>
		/// <param name="op"></param>
		/// <returns></returns>
		public static int SSL_CTX_set_mode(IntPtr ctx, int op)
		{
			return SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, IntPtr.Zero);
		}

		/// <summary>
		/// #define SSL_CTX_set_options in ssl.h - calls SSL_CTX_ctrl
		/// </summary>
		/// <param name="ctx"></param>
		/// <param name="op"></param>
		/// <returns></returns>
		public static int SSL_CTX_set_options(IntPtr ctx, int op)
		{
			return SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, op, IntPtr.Zero);
		}

		/// <summary>
		/// #define SSL_CTX_get_mode in ssl.h - calls SSL_CTX_ctrl
		/// </summary>
		/// <param name="ctx"></param>
		/// <returns></returns>
		public static int SSL_CTX_get_mode(IntPtr ctx)
		{
			return SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, 0, IntPtr.Zero);
		}

		/// <summary>
		/// #define SSL_CTX_get_options in ssl.h - calls SSL_CTX_ctrl
		/// </summary>
		/// <param name="ctx"></param>
		/// <returns>Int32 representation of options set in the context</returns>
		public static int SSL_CTX_get_options(IntPtr ctx)
		{
			return SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, 0, IntPtr.Zero);
		}

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_CTX_set_cert_store(IntPtr ctx, IntPtr cert_store);

		public const int SSL_VERIFY_NONE = 0x00;
		public const int SSL_VERIFY_PEER = 0x01;
		public const int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
		public const int SSL_VERIFY_CLIENT_ONCE = 0x04;

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_CTX_set_verify(IntPtr ctx, int mode, VerifyCertCallback callback);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_CTX_set_verify_depth(IntPtr ctx, int depth);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_CTX_set_client_CA_list(IntPtr ctx, IntPtr name_list);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_CTX_get_client_CA_list(IntPtr ctx);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_load_verify_locations(IntPtr ctx, string file, string path);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_set_default_verify_paths(IntPtr ctx);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_set_cipher_list(IntPtr ctx, string cipher_string);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_use_certificate_chain_file(IntPtr ctx, string file);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_use_certificate(IntPtr ctx, IntPtr cert);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_use_PrivateKey(IntPtr ctx, IntPtr pkey);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_check_private_key(IntPtr ctx);

		public const int SSL_MAX_SID_CTX_LENGTH = 32;

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CTX_set_session_id_context(IntPtr ctx, byte[] sid_ctx, uint sid_ctx_len);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_CTX_set_default_passwd_cb_userdata(IntPtr ssl, IntPtr data);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_CTX_set_default_passwd_cb(IntPtr ssl, pem_password_cb callback);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_CTX_set_client_cert_cb(IntPtr ssl_ctx, client_cert_cb callback);

		#endregion

		#region SSL functions
		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_CIPHER_description(IntPtr ssl_cipher, byte[] buf, int buf_len);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static string SSL_CIPHER_name(IntPtr ssl_cipher);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_CIPHER_get_bits(IntPtr ssl_cipher, out int alg_bits);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_get_current_cipher(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_get_verify_result(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_set_verify_result(IntPtr ssl, int v);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_get_peer_certificate(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_get_error(IntPtr ssl, int ret_code);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_accept(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_shutdown(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_write(IntPtr ssl, byte[] buf, int len);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_read(IntPtr ssl, byte[] buf, int len);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_renegotiate(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_set_session_id_context(IntPtr ssl, byte[] sid_ctx, uint sid_ctx_len);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_do_handshake(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_set_connect_state(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_set_accept_state(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_connect(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_new(IntPtr ctx);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_free(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_set_bio(IntPtr ssl, IntPtr read_bio, IntPtr write_bio);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_use_certificate_file(IntPtr ssl, string file, int type);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_use_PrivateKey_file(IntPtr ssl, string file, int type);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_clear(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_load_client_CA_file(string file);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_get_client_CA_list(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static void SSL_set_client_CA_list(IntPtr ssl, IntPtr name_list);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr SSL_get_certificate(IntPtr ssl);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_use_certificate(IntPtr ssl, IntPtr x509);

		[DllImport(SSLDLLNAME, CallingConvention=CallingConvention.Cdecl)]
		public extern static int SSL_use_PrivateKey(IntPtr ssl, IntPtr evp_pkey);

		#endregion

		#endregion

		#region Utilties
		public static string PtrToStringAnsi(IntPtr ptr, bool hasOwnership)
		{
			int len = 0;
			for (int i = 0; i < 1024; i++, len++)
			{
				byte octet = Marshal.ReadByte(ptr, i);
				if (octet == 0)
					break;
			}

			if (len == 1024)
				return "Invalid string";

			byte[] buf = new byte[len];
			Marshal.Copy(ptr, buf, 0, len);
			if (hasOwnership)
				Native.OPENSSL_free(ptr);
			return Encoding.ASCII.GetString(buf, 0, len);
		}

		public static IntPtr ExpectNonNull(IntPtr ptr)
		{
			if (ptr == IntPtr.Zero)
				throw new OpenSslException();
			return ptr;
		}

		public static int ExpectSuccess(int ret)
		{
			if (ret <= 0)
				throw new OpenSslException();
			return ret;
		}

		public static int TextToNID(string text)
		{
			int nid = Native.OBJ_txt2nid(text);
			if (nid == Native.NID_undef)
				throw new OpenSslException();
			return nid;
		}
		#endregion
	}

	class NameCollector
	{
		[StructLayout(LayoutKind.Sequential)]
		struct OBJ_NAME
		{
			public int type;
			public int alias;
			public IntPtr name;
			public IntPtr data;
		};

		private List<string> list = new List<string>();
		public List<string> Result { get { return this.list; } }

		public NameCollector(int type, bool isSorted)
		{
			if (isSorted)
				Native.OBJ_NAME_do_all_sorted(type, this.OnObjectName, IntPtr.Zero);
			else
				Native.OBJ_NAME_do_all(type, this.OnObjectName, IntPtr.Zero);
		}

		private void OnObjectName(IntPtr ptr, IntPtr arg)
		{
			OBJ_NAME name = (OBJ_NAME)Marshal.PtrToStructure(ptr, typeof(OBJ_NAME));
			string str = Native.PtrToStringAnsi(name.name, false);
			this.list.Add(str);
		}
	}
}
