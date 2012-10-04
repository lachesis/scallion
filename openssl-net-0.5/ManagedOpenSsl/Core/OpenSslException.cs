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
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace OpenSSL.Core
{
	/// <summary>
	/// This is a struct that contains a uint for the native openssl error code.
	/// It provides helper methods to convert this error code into strings.
	/// </summary>
	public struct OpenSslError
	{
		private uint err;

		/// <summary>
		/// Constructs an OpenSslError object.
		/// </summary>
		/// <param name="err">The native error code</param>
		public OpenSslError(uint err)
		{
			this.err = err;
		}

		/// <summary>
		/// Returns the native error code
		/// </summary>
		public uint ErrorCode
		{
			get { return this.err; }
		}

		/// <summary>
		/// Returns the result of ERR_lib_error_string()
		/// </summary>
		public string Library
		{
			get { return Native.PtrToStringAnsi(Native.ERR_lib_error_string(this.err), false); }
		}

		/// <summary>
		/// Returns the results of ERR_reason_error_string()
		/// </summary>
		public string Reason
		{
			get { return Native.PtrToStringAnsi(Native.ERR_reason_error_string(this.err), false); }
		}

		/// <summary>
		/// Returns the results of ERR_func_error_string()
		/// </summary>
		public string Function
		{
			get { return Native.PtrToStringAnsi(Native.ERR_func_error_string(this.err), false); }
		}

		/// <summary>
		/// Returns the results of ERR_error_string_n()
		/// </summary>
		public string Message
		{
			get
			{
				byte[] buf = new byte[1024];
				buf.Initialize();
				Native.ERR_error_string_n(err, buf, buf.Length);
				int len;
				for (len = 0; len < buf.Length; len++) 
				{
					if (buf[len] == 0)
						break;
				}
				return Encoding.ASCII.GetString(buf, 0, len);
			}
		}
	}

	/// <summary>
	/// Exception class to provide OpenSSL specific information when errors occur.
	/// </summary>
	public class OpenSslException : Exception
	{
		private List<OpenSslError> errors = new List<OpenSslError>();

		private OpenSslException(List<OpenSslError> context)
			: base(GetErrorMessage(context))
		{
			this.errors = context;
		}

		/// <summary>
		/// When this class is instantiated, GetErrorMessage() is called automatically.
		/// This will call ERR_get_error() on the native openssl interface, once for every
		/// error that is in the current context. The exception message is the concatination
		/// of each of these errors turned into strings using ERR_error_string_n().
		/// </summary>
		public OpenSslException()
			: this(GetCurrentContext())
		{
		}

        private static List<OpenSslError> GetCurrentContext()
		{
			List<OpenSslError> ret = new List<OpenSslError>();
			while (true)
			{
				uint err = Native.ERR_get_error();
				if (err == 0)
					break;

				ret.Add(new OpenSslError(err));
			}
			return ret;
		}

		private static string GetErrorMessage(List<OpenSslError> context)
		{
			StringBuilder sb = new StringBuilder();
			bool isFirst = true;
			foreach (OpenSslError err in context)
			{
				if (isFirst)
					isFirst = false;
				else
					sb.Append("\n");
				sb.Append(err.Message);
			}

			return sb.ToString();
		}

		/// <summary>
		/// Returns the list of errors associated with this exception.
		/// </summary>
		public List<OpenSslError> Errors
		{
			get { return this.errors; }
		}
	}
}
