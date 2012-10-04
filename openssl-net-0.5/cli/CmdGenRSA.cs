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
using System.IO;
using OpenSSL.Core;
using OpenSSL.Crypto;

namespace OpenSSL.CLI
{
	class CmdGenRSA : ICommand
	{
		OptionParser options = new OptionParser();

		public CmdGenRSA()
		{
			options.AddOption("-des", new Option("des", false));
			options.AddOption("-des3", new Option("des3", false));
			options.AddOption("-idea", new Option("idea", false));
			options.AddOption("-aes128", new Option("aes128", false));
			options.AddOption("-aes192", new Option("aes192", false));
			options.AddOption("-aes256", new Option("aes256", false));
			options.AddOption("-out", new Option("out", ""));
			options.AddOption("-passout", new Option("passout", ""));
			options.AddOption("-f4", new Option("f4", true));
			options.AddOption("-3", new Option("3", false));
			options.AddOption("-engine", new Option("engine", ""));
			options.AddOption("-rand", new Option("rand", ""));
		}

		void Usage()
		{
			Console.Error.WriteLine(
@"usage: genrsa [args] [numbits]
 -des            encrypt the generated key with DES in cbc mode
 -des3           encrypt the generated key with DES in ede cbc mode (168 bit key)
 -idea           encrypt the generated key with IDEA in cbc mode
 -aes128, -aes192, -aes256
                 encrypt PEM output with cbc aes
 -out file       output the key to 'file
 -passout arg    output file pass phrase source
 -f4             use F4 (0x10001) for the E value
 -3              use 3 for the E value
 -engine e       use engine e, possibly a hardware device.
 -rand file;file;...
                 load the file (or the files in the directory) into
                 the random number generator");
		}

		#region ICommand Members

		public void Execute(string[] args)
		{
			try
			{
				options.ParseArguments(args);
			}
			catch (Exception)
			{
				Usage();
				return;
			}

			int bits = 512;
			if (this.options.Arguments.Count == 1)
				bits = Convert.ToInt32(this.options.Arguments[0]);

			BigNumber e = null;
			if (options.IsSet("3"))
				e = 3;
			else if (options.IsSet("f4"))
				e = 0x10001;

			Console.Error.WriteLine("Generating RSA private key, {0} bit long modulus", bits);

			RSA rsa = new RSA();
			rsa.GenerateKeys(bits, e, Program.OnGenerator, null);

			Console.Error.WriteLine("e is {0} (0x{1})", e.ToDecimalString(), e.ToHexString());

			Cipher enc = null;
			if (options.IsSet("des"))
				enc = Cipher.DES_CBC;
			else if (options.IsSet("des3"))
				enc = Cipher.DES_EDE3_CBC;
			else if (options.IsSet("idea"))
				enc = Cipher.Idea_CBC;
			else if (options.IsSet("aes128"))
				enc = Cipher.AES_128_CBC;
			else if (options.IsSet("aes192"))
				enc = Cipher.AES_192_CBC;
			else if (options.IsSet("aes256"))
				enc = Cipher.AES_256_CBC;

			using (BIO bio = BIO.MemoryBuffer())
			{
				rsa.WritePrivateKey(bio, enc, Program.OnPassword, this.options["passout"]);

				string outfile = this.options["out"] as string;
				if (string.IsNullOrEmpty(outfile))
					Console.WriteLine(bio.ReadString());
				else
					File.WriteAllText(outfile, bio.ReadString());
			}
		}

		#endregion
	}
}
