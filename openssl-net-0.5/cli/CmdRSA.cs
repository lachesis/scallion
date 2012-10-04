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
using OpenSSL.Core;
using OpenSSL.Crypto;

namespace OpenSSL.CLI
{
	class CmdRSA : ICommand
	{
		OptionParser options = new OptionParser();

		public CmdRSA()
		{
			options.AddOption("-inform", new Option("inform", "PEM"));
			options.AddOption("-outform", new Option("outform", "PEM"));
			options.AddOption("-in", new Option("in", ""));
			options.AddOption("-sgckey", new Option("sgckey", false));
			options.AddOption("-passin", new Option("passin", ""));
			options.AddOption("-out", new Option("out", ""));
			options.AddOption("-passout", new Option("passout", "passout"));
			options.AddOption("-des", new Option("des", false));
			options.AddOption("-des3", new Option("des3", false));
			options.AddOption("-aes128", new Option("aes128", false));
			options.AddOption("-aes192", new Option("aes192", false));
			options.AddOption("-aes256", new Option("aes256", false));
			options.AddOption("-text", new Option("text", false));
			options.AddOption("-noout", new Option("noout", false));
			options.AddOption("-modulus", new Option("modulus", false));
			options.AddOption("-check", new Option("check", false));
			options.AddOption("-pubin", new Option("pubin", false));
			options.AddOption("-pubout", new Option("pubout", false));
			options.AddOption("-engine", new Option("engine", ""));
		}

		void Usage()
		{
			Console.Error.WriteLine(
@"rsa [options] <infile >outfile
where options are
 -inform arg     input format - one of DER NET PEM
 -outform arg    output format - one of DER NET PEM
 -in arg         input file
 -sgckey         Use IIS SGC key format
 -passin arg     input file pass phrase source
 -out arg        output file
 -passout arg    output file pass phrase source
 -des            encrypt PEM output with cbc des
 -des3           encrypt PEM output with ede cbc des using 168 bit key
 -aes128, -aes192, -aes256
                 encrypt PEM output with cbc aes
 -text           print the key in text
 -noout          don't print key out
 -modulus        print the RSA key modulus
 -check          verify key consistency
 -pubin          expect a public key in input file
 -pubout         output a public key
 -engine e       use engine e, possibly a hardware device.");
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

			if (options.IsSet("pubin") && options.IsSet("check"))
			{
				Console.Error.WriteLine("Only private keys can be checked");
				return;
			}

			BIO bin = Program.GetInFile(options.GetString("in"));

			RSA rsa;
			if (options.IsSet("pubin"))
				rsa = RSA.FromPublicKey(bin, Program.OnPassword, this.options["passin"]);
			else
				rsa = RSA.FromPrivateKey(bin, Program.OnPassword, this.options["passin"]);

			Cipher enc = null;
			if (options.IsSet("des"))
				enc = Cipher.DES_CBC;
			else if (options.IsSet("des3"))
				enc = Cipher.DES_EDE3_CBC;
			else if (options.IsSet("aes128"))
				enc = Cipher.AES_128_CBC;
			else if (options.IsSet("aes192"))
				enc = Cipher.AES_192_CBC;
			else if (options.IsSet("aes256"))
				enc = Cipher.AES_256_CBC;

			if (options.IsSet("text"))
				Console.Write(rsa);

			if (options.IsSet("modulus"))
				Console.WriteLine("Modulus={0}", rsa.PublicModulus);

			if (options.IsSet("check"))
			{
				if (rsa.Check())
					Console.WriteLine("RSA key ok");
				else
					Console.WriteLine("RSA key error");
			}

			if (!options.IsSet("noout"))
			{
				Console.Error.WriteLine("writing RSA key");
				using (BIO bio = BIO.MemoryBuffer())
				{
					if (this.options.IsSet("pubout"))
						rsa.WritePublicKey(bio);
					else
						rsa.WritePrivateKey(bio, enc, Program.OnPassword, this.options["passout"]);

					string outfile = this.options["out"] as string;
					if (string.IsNullOrEmpty(outfile))
						Console.WriteLine(bio.ReadString());
					else
						File.WriteAllText(outfile, bio.ReadString());
				}
			}
		}

		#endregion
	}
}
