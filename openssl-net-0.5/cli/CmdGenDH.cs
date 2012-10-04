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
using OpenSSL;
using OpenSSL.Crypto;

namespace OpenSSL.CLI
{
	class CmdGenDH : ICommand
	{
		OptionParser options = new OptionParser();
		public CmdGenDH()
		{
			options.AddOption("-out", new Option("out", ""));
			options.AddOption("-2", new Option("2", false));
			options.AddOption("-5", new Option("5", false));
			options.AddOption("-rand", new Option("rand", ""));
			options.AddOption("-engine", new Option("engine", ""));
		}

		void Usage()
		{
			string str =
@"usage: gendh [args] [numbits]
 -out file - output the key to 'file
 -2        - use 2 as the generator value
 -5        - use 5 as the generator value
 -engine e - use engine e, possibly a hardware device.
 -rand file:file:...
           - load the file (or the files in the directory) into
             the random number generator";

			Console.Error.WriteLine(str);
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

			int g = DH.Generator2;
			if (this.options.IsSet("2"))
				g = DH.Generator2;

			if (this.options.IsSet("5"))
				g = DH.Generator5;

			int bits = 512;
			if (this.options.Arguments.Count == 1)
				bits = Convert.ToInt32(this.options.Arguments[0]);

			Console.Error.WriteLine("Generating DH parameters, {0} bit long safe prime, generator {1}", bits, g);
			Console.Error.WriteLine("This is going to take a long time");

			DH dh = new DH(bits, g, Program.OnGenerator, null);

			string outfile = this.options["out"] as string;
			if (string.IsNullOrEmpty(outfile))
			{
				Console.WriteLine(dh.PEM);
			}
			else
			{
				File.WriteAllText(outfile, dh.PEM);
			}
		}

		#endregion
	}
}
