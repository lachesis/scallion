// Copyright (c) 2006-2009 Frank Laub
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
using System.Reflection;

namespace OpenSSL.Core
{
	/// <summary>
	/// Base class for all openssl wrapped objects. 
	/// Contains the raw unmanaged pointer and has a Handle property to get access to it. 
	/// Also overloads the ToString() method with a BIO print.
	/// </summary>
	public abstract class Base : IDisposable
	{
		/// <summary>
		/// Constructor which takes the raw unmanged pointer. 
		/// This is the only way to construct this object and all dervied types.
		/// </summary>
		/// <param name="ptr"></param>
		/// <param name="takeOwnership"></param>
		protected Base(IntPtr ptr, bool takeOwnership)
		{
			this.ptr = ptr;
			this.owner = takeOwnership;
			if (this.ptr != IntPtr.Zero)
			{
				this.OnNewHandle(this.ptr);
			}
		}

		/// <summary>
		/// This finalizer just calls Dispose().
		/// </summary>
		~Base()
		{
			Dispose();
		}

		/// <summary>
		/// This method is used by the ToString() implementation. A great number of
		/// openssl objects support printing, so this is a conveinence method.
		/// Dervied types should override this method and not ToString().
		/// </summary>
		/// <param name="bio">The BIO stream object to print into</param>
		public virtual void Print(BIO bio) { }

		/// <summary>
		/// Override of ToString() which uses Print() into a BIO memory buffer.
		/// </summary>
		/// <returns></returns>
		public override string ToString() {
			try {
				if (this.ptr == IntPtr.Zero)
					return "(null)";

				using (BIO bio = BIO.MemoryBuffer()) {
					this.Print(bio);
					return bio.ReadString();
				}
			}
			catch (Exception) {
				return "<exception>";
			}
		}

		/// <summary>
		/// This method must be implemented in derived classes.
		/// </summary>
		protected abstract void OnDispose();

		/// <summary>
		/// Do nothing in the base class.
		/// </summary>
		/// <param name="ptr"></param>
		internal virtual void OnNewHandle(IntPtr ptr)
		{
		}

		#region IDisposable Members

		/// <summary>
		/// Implementation of the IDisposable interface.
		/// If the native pointer is not null, we haven't been disposed, and we are the owner,
		/// then call the virtual OnDispose() method.
		/// </summary>
		public void Dispose() {
			if (!this.isDisposed && this.owner && this.ptr != IntPtr.Zero) {
				this.OnDispose();
				DoAfterDispose();
			}
			this.isDisposed = true;
		}

		#endregion

		/// <summary>
		/// gets/sets whether the object owns the Native pointer
		/// </summary>
		public virtual bool IsOwner
		{
			get { return owner; }
			internal set { owner = value; }
		}

		/// <summary>
		/// Access to the raw unmanaged pointer.
		/// </summary>
		public virtual IntPtr Handle
		{
			get { return this.ptr; }
		}

		/// <summary>
		/// Throws NotImplementedException
		/// </summary>
		internal virtual void AddRef()
		{
			throw new NotImplementedException();
		}

		private void DoAfterDispose()
		{
			this.ptr = IntPtr.Zero;
			GC.SuppressFinalize(this);
		}

		/// <summary>
		/// Raw unmanaged pointer
		/// </summary>
		protected IntPtr ptr;

		/// <summary>
		/// If this object is the owner, then call the appropriate native free function.
		/// </summary>
		protected bool owner = false;

		/// <summary>
		/// This is to prevent double-deletion issues.
		/// </summary>
		protected bool isDisposed = false;

	}

	/// <summary>
	/// Helper type that handles the AddRef() method.
	/// Derived classes must implement the <code>LockType</code> and <code>RawReferenceType</code> properties
	/// </summary>
	public abstract class BaseReferenceType : Base
	{
		internal BaseReferenceType(IntPtr ptr, bool takeOwnership)
			: base(ptr, takeOwnership)
		{
			this.baseOffset = Marshal.OffsetOf(RawReferenceType, "references");
		}

		internal override void AddRef()
		{
			IntPtr offset = GetReferencesOffset();
			Native.CRYPTO_add_lock(offset, 1, LockType, "Base.cs", 0);
		}

		/// <summary>
		/// Prints the current underlying reference count
		/// </summary>
		public void PrintRefCount()
		{
			IntPtr offset = GetReferencesOffset();
			int count = Marshal.ReadInt32(offset);
			Console.WriteLine("{0} ptr: {1}, ref_count: {2}", this.GetType().Name, this.ptr, count);
		}

		private IntPtr GetReferencesOffset()
		{
			return new IntPtr((long)this.ptr + (long)this.baseOffset);
		}

		/// <summary>
		/// Derived classes must return a <code>CryptoLockTypes</code> for this type
		/// </summary>
		internal abstract CryptoLockTypes LockType { get; }

		/// <summary>
		/// Derived classes must return a <code>Type</code> that matches the underlying type
		/// </summary>
		internal abstract Type RawReferenceType { get; }

		private IntPtr baseOffset;
	}

	/// <summary>
	/// Implements the CopyRef() method
	/// </summary>
	/// <typeparam name="T"></typeparam>
	public abstract class BaseCopyableRef<T> : BaseReferenceType where T : BaseCopyableRef<T>
	{
		internal BaseCopyableRef(IntPtr ptr, bool takeOwnership)
			: base(ptr, takeOwnership)
		{
		}

		internal T CopyRef()
		{
			object[] args = new object[] {
				this.ptr,
				true
			};
			BindingFlags flags =
				BindingFlags.NonPublic |
				BindingFlags.Public |
				BindingFlags.Instance;
			T ret = (T)Activator.CreateInstance(typeof(T), flags, null, args, null);
			ret.AddRef();
			return ret;
		}
	}

	/// <summary>
	/// Helper base class that handles the AddRef() method by using a _dup() method.
	/// </summary>
	public abstract class BaseValueType : Base
	{
		internal BaseValueType(IntPtr ptr, bool takeOwnership)
			: base(ptr, takeOwnership)
		{
		}

		internal override void AddRef()
		{
			this.ptr = DuplicateHandle();
			this.owner = true;
			if (this.ptr != IntPtr.Zero)
			{
				this.OnNewHandle(this.ptr);
			}
		}

		/// <summary>
		/// Derived classes must use a _dup() method to make a copy of the underlying native data structure.
		/// </summary>
		/// <returns></returns>
		internal abstract IntPtr DuplicateHandle();
	}
}
