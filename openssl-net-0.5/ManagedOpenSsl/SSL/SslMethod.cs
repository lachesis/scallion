// Copyright (c) 2009 Ben Henderson
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
using OpenSSL.Core;

namespace OpenSSL.SSL
{
    /// <summary>
    /// Wraps the SSL_METHOD structure and methods
    /// </summary>
    public class SslMethod : Base
    {
        private SslMethod(IntPtr ptr, bool owner) :
            base(ptr, owner)
        {
        }

		/// <summary>
		/// Throws NotImplementedException()
		/// </summary>
		protected override void OnDispose() {
			throw new NotImplementedException();
		}

        /// <summary>
        /// SSLv2_method()
        /// </summary>
        public static SslMethod SSLv2_method = new SslMethod(Native.SSLv2_method(), false);

        /// <summary>
        /// SSLv2_server_method()
        /// </summary>
        public static SslMethod SSLv2_server_method = new SslMethod(Native.SSLv2_server_method(), false);

        /// <summary>
        /// SSLv2_client_method()
        /// </summary>
        public static SslMethod SSLv2_client_method = new SslMethod(Native.SSLv2_client_method(), false);
        
        /// <summary>
        /// SSLv3_method()
        /// </summary>
        public static SslMethod SSLv3_method = new SslMethod(Native.SSLv3_method(), false);

        /// <summary>
        /// SSLv3_server_method()
        /// </summary>
        public static SslMethod SSLv3_server_method = new SslMethod(Native.SSLv3_server_method(), false);

        /// <summary>
        /// SSLv3_client_method()
        /// </summary>
        public static SslMethod SSLv3_client_method = new SslMethod(Native.SSLv3_client_method(), false);

        /// <summary>
        /// SSLv23_method()
        /// </summary>
        public static SslMethod SSLv23_method = new SslMethod(Native.SSLv23_method(), false);

        /// <summary>
        /// SSLv23_server_method()
        /// </summary>
        public static SslMethod SSLv23_server_method = new SslMethod(Native.SSLv23_server_method(), false);

        /// <summary>
        /// SSLv23_client_method()
        /// </summary>
        public static SslMethod SSLv23_client_method = new SslMethod(Native.SSLv23_client_method(), false);

        /// <summary>
        /// TLSv1_method()
        /// </summary>
        public static SslMethod TLSv1_method = new SslMethod(Native.TLSv1_method(), false);

        /// <summary>
        /// TLSv1_server_method()
        /// </summary>
        public static SslMethod TLSv1_server_method = new SslMethod(Native.TLSv1_server_method(), false);

        /// <summary>
        /// TLSv1_client_method()
        /// </summary>
        public static SslMethod TLSv1_client_method = new SslMethod(Native.TLSv1_client_method(), false);

        /// <summary>
        /// DTLSv1_method()
        /// </summary>
        public static SslMethod DTLSv1_method = new SslMethod(Native.DTLSv1_method(), false);

        /// <summary>
        /// DTLSv1_server_method()
        /// </summary>
        public static SslMethod DTLSv1_server_method = new SslMethod(Native.DTLSv1_server_method(), false);

        /// <summary>
        /// DTLSv1_client_method()
        /// </summary>
        public static SslMethod DTLSv1_client_method = new SslMethod(Native.DTLSv1_client_method(), false);

    }
}
