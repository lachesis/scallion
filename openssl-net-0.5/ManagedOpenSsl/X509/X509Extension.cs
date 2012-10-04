// Copyright (c) 2009 Frank Laub
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
using OpenSSL.Core;

namespace OpenSSL.X509
{
	/// <summary>
	/// Wraps the X509_EXTENSION object
	/// </summary>
	public class X509Extension : BaseValueType, IStackable
	{
		#region Initialization

		/// <summary>
		/// Calls X509_EXTENSION_new()
		/// </summary>
		public X509Extension()
			: base(Native.ExpectNonNull(Native.X509_EXTENSION_new()), true)
		{ }

		internal X509Extension(IStack stack, IntPtr ptr)
			: base(ptr, true)
		{ }

		/// <summary>
		/// Calls X509V3_EXT_conf_nid()
		/// </summary>
		/// <param name="issuer"></param>
		/// <param name="subject"></param>
		/// <param name="name"></param>
		/// <param name="critical"></param>
		/// <param name="value"></param>
		public X509Extension(X509Certificate issuer, X509Certificate subject, string name, bool critical, string value)
			: base(IntPtr.Zero, true)
		{
			using (X509V3Context ctx = new X509V3Context(issuer, subject, null))
			{
				this.ptr = Native.ExpectNonNull(Native.X509V3_EXT_conf_nid(IntPtr.Zero, ctx.Handle, Native.TextToNID(name), value));
			}
		}

		#endregion

		#region Properties

		/// <summary>
		/// Uses X509_EXTENSION_get_object() and OBJ_nid2ln()
		/// </summary>
		public string Name
		{
			get { return Native.OBJ_nid2ln(this.NID); }
		}

		/// <summary>
		/// Uses X509_EXTENSION_get_object() and OBJ_obj2nid()
		/// </summary>
		public int NID
		{
			get
			{
				// Don't free the obj_ptr
				IntPtr obj_ptr = Native.X509_EXTENSION_get_object(this.ptr);
				if (obj_ptr != IntPtr.Zero)
					return Native.OBJ_obj2nid(obj_ptr);
				return 0;
			}
		}

		/// <summary>
		/// returns X509_EXTENSION_get_critical()
		/// </summary>
		public bool IsCritical
		{
			get
			{
				int nCritical = Native.X509_EXTENSION_get_critical(this.ptr);
				return (nCritical == 1);
			}
		}

		/// <summary>
		/// Returns X509_EXTENSION_get_data()
		/// </summary>
		public byte[] Data
		{
			get
			{
				using (Asn1String str = new Asn1String(Native.X509_EXTENSION_get_data(this.ptr), false))
				{
					return str.Data;
				}
			}
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls X509_EXTENSION_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.X509_EXTENSION_free(this.ptr);
		}

		/// <summary>
		/// Calls X509V3_EXT_print()
		/// </summary>
		/// <param name="bio"></param>
		public override void Print(BIO bio)
		{
			Native.X509V3_EXT_print(bio.Handle, this.ptr, 0, 0);
		}

		/// <summary>
		/// Calls X509_EXTENSION_dup()
		/// </summary>
		/// <returns></returns>
		internal override IntPtr DuplicateHandle()
		{
			return Native.X509_EXTENSION_dup(this.ptr);
		}

		#endregion
	}

	/// <summary>
	/// X509 Extension entry
	/// </summary>
	public class X509V3ExtensionValue
	{
		#region Initialization
		/// <summary>
		/// </summary>
		/// <param name="name"></param>
		/// <param name="critical"></param>
		/// <param name="value"></param>
		public X509V3ExtensionValue(string name, bool critical, string value)
		{
			this.name = name;
			this.critical = critical;
			this.value = value;
		}
		#endregion

		#region Properties

		/// <summary>
		/// </summary>
		public string Name
		{
			get { return name; }
		}

		/// <summary>
		/// </summary>
		public bool IsCritical
		{
			get { return critical; }
		}

		/// <summary>
		/// </summary>
		public string Value
		{
			get { return this.value; }
		}

		#endregion

		#region Fields
		private bool critical;
		private string value;
		private string name;
		#endregion
	}

	/// <summary>
	/// Dictionary for X509 v3 extensions - Name, Value 
	/// </summary>
	public class X509V3ExtensionList : List<X509V3ExtensionValue>
	{
	}

}
