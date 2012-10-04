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
	
namespace OpenSSL.X509
{
	/// <summary>
	/// X509_V_*
	/// </summary>
	public enum VerifyResult
	{
		/// <summary>
		/// X509_V_OK 
		/// </summary>
		X509_V_OK = 0,
		/* illegal error (for uninitialized values, to avoid X509_V_OK): 1 */
		/// <summary>
		/// X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
		/// </summary>
		X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2,
		/// <summary>
		/// X509_V_ERR_UNABLE_TO_GET_CRL 
		/// </summary>
		X509_V_ERR_UNABLE_TO_GET_CRL = 3,
		/// <summary>
		/// X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE 
		/// </summary>
		X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4,
		/// <summary>
		/// X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE 
		/// </summary>
		X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5,
		/// <summary>
		/// X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY 
		/// </summary>
		X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6,
		/// <summary>
		/// X509_V_ERR_CERT_SIGNATURE_FAILURE 
		/// </summary>
		X509_V_ERR_CERT_SIGNATURE_FAILURE = 7,
		/// <summary>
		/// X509_V_ERR_CRL_SIGNATURE_FAILURE 
		/// </summary>
		X509_V_ERR_CRL_SIGNATURE_FAILURE = 8,
		/// <summary>
		/// X509_V_ERR_CERT_NOT_YET_VALID 
		/// </summary>
		X509_V_ERR_CERT_NOT_YET_VALID = 9,
		/// <summary>
		/// X509_V_ERR_CERT_HAS_EXPIRED 
		/// </summary>
		X509_V_ERR_CERT_HAS_EXPIRED = 10,
		/// <summary>
		/// X509_V_ERR_CRL_NOT_YET_VALID 
		/// </summary>
		X509_V_ERR_CRL_NOT_YET_VALID = 11,
		/// <summary>
		/// X509_V_ERR_CRL_HAS_EXPIRED 
		/// </summary>
		X509_V_ERR_CRL_HAS_EXPIRED = 12,
		/// <summary>
		/// X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD 
		/// </summary>
		X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13,
		/// <summary>
		/// X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD 
		/// </summary>
		X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14,
		/// <summary>
		/// X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD 
		/// </summary>
		X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15,
		/// <summary>
		/// X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD 
		/// </summary>
		X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16,
		/// <summary>
		/// X509_V_ERR_OUT_OF_MEM 
		/// </summary>
		X509_V_ERR_OUT_OF_MEM = 17,
		/// <summary>
		/// X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT 
		/// </summary>
		X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18,
		/// <summary>
		/// X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN 
		/// </summary>
		X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19,
		/// <summary>
		/// X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY 
		/// </summary>
		X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20,
		/// <summary>
		/// X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE 
		/// </summary>
		X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21,
		/// <summary>
		/// X509_V_ERR_CERT_CHAIN_TOO_LONG 
		/// </summary>
		X509_V_ERR_CERT_CHAIN_TOO_LONG = 22,
		/// <summary>
		/// X509_V_ERR_CERT_REVOKED 
		/// </summary>
		X509_V_ERR_CERT_REVOKED = 23,
		/// <summary>
		/// X509_V_ERR_INVALID_CA 
		/// </summary>
		X509_V_ERR_INVALID_CA = 24,
		/// <summary>
		/// X509_V_ERR_PATH_LENGTH_EXCEEDED 
		/// </summary>
		X509_V_ERR_PATH_LENGTH_EXCEEDED = 25,
		/// <summary>
		/// X509_V_ERR_INVALID_PURPOSE 
		/// </summary>
		X509_V_ERR_INVALID_PURPOSE = 26,
		/// <summary>
		/// X509_V_ERR_CERT_UNTRUSTED 
		/// </summary>
		X509_V_ERR_CERT_UNTRUSTED = 27,
		/// <summary>
		/// X509_V_ERR_CERT_REJECTED 
		/// </summary>
		X509_V_ERR_CERT_REJECTED = 28,

		/* These are 'informational' when looking for issuer cert */
		/// <summary>
		/// X509_V_ERR_SUBJECT_ISSUER_MISMATCH 
		/// </summary>
		X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29,
		/// <summary>
		/// X509_V_ERR_AKID_SKID_MISMATCH 
		/// </summary>
		X509_V_ERR_AKID_SKID_MISMATCH = 30,
		/// <summary>
		/// X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH 
		/// </summary>
		X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31,
		/// <summary>
		/// X509_V_ERR_KEYUSAGE_NO_CERTSIGN 
		/// </summary>
		X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32,

		/// <summary>
		/// X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER 
		/// </summary>
		X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33,
		/// <summary>
		/// X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION 
		/// </summary>
		X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34,
		/// <summary>
		/// X509_V_ERR_KEYUSAGE_NO_CRL_SIGN 
		/// </summary>
		X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = 35,
		/// <summary>
		/// X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION 
		/// </summary>
		X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36,
		/// <summary>
		/// X509_V_ERR_INVALID_NON_CA 
		/// </summary>
		X509_V_ERR_INVALID_NON_CA = 37,
		/// <summary>
		/// X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED 
		/// </summary>
		X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38,
		/// <summary>
		/// X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE 
		/// </summary>
		X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39,
		/// <summary>
		/// X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED 
		/// </summary>
		X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40,
		/// <summary>
		/// X509_V_ERR_APPLICATION_VERIFICATION 
		/// </summary>
		X509_V_ERR_APPLICATION_VERIFICATION = 50
	}

}
