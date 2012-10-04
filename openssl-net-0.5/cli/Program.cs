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
using OpenSSL;
using System.IO;
using System.Runtime.InteropServices;
using OpenSSL.Core;
using OpenSSL.Crypto;

namespace OpenSSL.CLI
{
	interface ICommand
	{
		void Execute(string[] args);
	}

	#region NullCommand
	class NullCommand : ICommand
	{
		private string name;
		public NullCommand(string name)
		{
			this.name = name;
		}

		#region ICommand Members
		public void Execute(string[] args)
		{
			Console.Error.WriteLine("{0}: {1}", this.name, string.Join(" ", args));
			Console.Error.WriteLine("Not implemented yet!");
		}
		#endregion
	}
	#endregion

	class Program
	{
		static void Main(string[] args)
		{
			Program program = new Program();
			program.Run(args);
		}

		SortedDictionary<string, ICommand> std_cmds = new SortedDictionary<string, ICommand>();
		SortedDictionary<string, ICommand> md_cmds = new SortedDictionary<string, ICommand>();
		SortedDictionary<string, ICommand> cipher_cmds = new SortedDictionary<string, ICommand>();

		void AddNullCommand(SortedDictionary<string, ICommand> map, string name)
		{
			map.Add(name, new NullCommand(name));
		}

		Program()
		{
			CmdCipher cmdCipher = new CmdCipher();
			CmdDigest cmdDigest = new CmdDigest();

			this.std_cmds.Add("dh", new CmdDH());
			this.std_cmds.Add("gendh", new CmdGenDH());
			this.std_cmds.Add("rsa", new CmdRSA());
			this.std_cmds.Add("genrsa", new CmdGenRSA());
			this.std_cmds.Add("version", new CmdVersion());
			this.std_cmds.Add("enc", cmdCipher);
			this.std_cmds.Add("dgst", cmdDigest);

			#region Standard Commands
			AddNullCommand(std_cmds, "asn1parse");
			AddNullCommand(std_cmds, "ca");
			AddNullCommand(std_cmds, "ciphers");
			AddNullCommand(std_cmds, "crl");
			AddNullCommand(std_cmds, "crl2pkcs7");
			AddNullCommand(std_cmds, "dhparam");
			AddNullCommand(std_cmds, "dsa");
			AddNullCommand(std_cmds, "dsaparam");
			AddNullCommand(std_cmds, "ec");
			AddNullCommand(std_cmds, "ecparam");
			AddNullCommand(std_cmds, "engine");
			AddNullCommand(std_cmds, "errstr");
			AddNullCommand(std_cmds, "gendsa");
			AddNullCommand(std_cmds, "nseq");
			AddNullCommand(std_cmds, "ocsp");
			AddNullCommand(std_cmds, "passwd");
			AddNullCommand(std_cmds, "pkcs12");
			AddNullCommand(std_cmds, "pkcs7");
			AddNullCommand(std_cmds, "pkcs8");
			AddNullCommand(std_cmds, "prime");
			AddNullCommand(std_cmds, "rand");
			AddNullCommand(std_cmds, "req");
			AddNullCommand(std_cmds, "rsautl");
			AddNullCommand(std_cmds, "s_client");
			AddNullCommand(std_cmds, "s_server");
			AddNullCommand(std_cmds, "s_time");
			AddNullCommand(std_cmds, "sess_id");
			AddNullCommand(std_cmds, "smime");
			AddNullCommand(std_cmds, "speed");
			AddNullCommand(std_cmds, "spkac");
			AddNullCommand(std_cmds, "verify");
			AddNullCommand(std_cmds, "x509");
			#endregion

			#region Message Digest commands
			foreach (string name in MessageDigest.AllNames) 
			{
				this.md_cmds.Add(name, cmdDigest);
			}
			#endregion

			#region Cipher commands
			foreach (string name in Cipher.AllNames) 
			{
				this.cipher_cmds.Add(name, cmdCipher);
			}
			#endregion
		}

		ICommand FindCommand(string name)
		{
			if (std_cmds.ContainsKey(name))
				return std_cmds[name];
			if (md_cmds.ContainsKey(name))
				return md_cmds[name];
			if (cipher_cmds.ContainsKey(name))
				return cipher_cmds[name];
			return null;
		}

		void PrintCommands(IEnumerable<string> cmds)
		{
			const int COLUMN_WIDTH = 15;
			int col = 0;
			foreach (string cmd in cmds)
			{
				if (cmd == cmd.ToUpper())
					continue;

				if (cmd.Length > COLUMN_WIDTH) 
				{
					if (col > 0) 
						Console.Error.WriteLine();
					Console.Error.Write(cmd.PadRight(COLUMN_WIDTH));
					Console.Error.WriteLine();
					col = 0;
				}
				else 
				{
					Console.Error.Write(cmd.PadRight(COLUMN_WIDTH));
					if (col++ == 4) 
					{
						Console.Error.WriteLine();
						col = 0;
						continue;
					}
				}

			}
			Console.Error.WriteLine();
		}

		void Usage()
		{
			Console.Error.WriteLine("Standard commands");
			PrintCommands(std_cmds.Keys);
			Console.Error.WriteLine();
			Console.Error.WriteLine("Message Digest commands");
			PrintCommands(md_cmds.Keys);
			Console.Error.WriteLine();
			Console.Error.WriteLine("Cipher commands");
			PrintCommands(cipher_cmds.Keys);
		}

		void Run(string[] args)
		{
			if (args.Length == 0)
			{
				Usage();
				return;
			}
			ICommand cmd = FindCommand(args[0]);
			if (cmd == null)
			{
				Usage();
				return;
			}

			cmd.Execute(args);
		}

		public static int OnGenerator(int p, int n, object arg)
		{
			TextWriter cout = Console.Error;

			switch (p)
			{
				case 0: cout.Write('.'); break;
				case 1: cout.Write('+'); break;
				case 2: cout.Write('*'); break;
				case 3: cout.WriteLine(); break;
			}

			return 1;
		}

		private static string ReadPassword()
		{
			Console.TreatControlCAsInput = true;
			StringBuilder sb = new StringBuilder();
			while (true)
			{
				ConsoleKeyInfo key = Console.ReadKey(true);
				if (key.Key == ConsoleKey.Enter)
					break;

				if (key.Key == ConsoleKey.C && key.Modifiers == ConsoleModifiers.Control)
				{
					Console.Error.WriteLine();
					throw new Exception("Cancelled");
				}

				sb.Append(key.KeyChar);
			}
			Console.TreatControlCAsInput = false;
			return sb.ToString();
		}

		public static string OnPassword(bool verify, object arg)
		{
			string passout = arg as string;
			if (!string.IsNullOrEmpty(passout))
				return File.ReadAllText(passout);

			while (true)
			{
				Console.Error.Write("Enter pass phrase:");
				string strPassword = ReadPassword();
				Console.Error.WriteLine();

				if (strPassword.Length == 0)
					continue;

				if (!verify)
					return strPassword;

				Console.Error.Write("Verifying - Enter pass phrase:");
				string strVerify = ReadPassword();
				Console.Error.WriteLine();
	
				if (strPassword == strVerify)
					return strPassword;

				Console.Error.WriteLine("Passwords don't match, try again.");
			}
		}

		public static BIO GetInFile(string infile)
		{
			BIO bio;
			if (string.IsNullOrEmpty(infile))
			{
				bio = BIO.MemoryBuffer();
				Stream cin = Console.OpenStandardInput();
				byte[] buf = new byte[1024];
				while (true)
				{
					int len = cin.Read(buf, 0, buf.Length);
					if (len == 0)
						break;
					bio.Write(buf, len);
				}
				return bio;
			}

			return BIO.File(infile, "r");
		}
	}
}
