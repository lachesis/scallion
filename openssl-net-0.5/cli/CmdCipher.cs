using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using OpenSSL.Core;
using OpenSSL.Crypto;

namespace OpenSSL.CLI {
	class CmdCipher : ICommand {
		OptionParser options = new OptionParser();

		public CmdCipher() {
			options.AddOption("-in", new Option("infile", ""));
			options.AddOption("-out", new Option("outfile", ""));
			options.AddOption("-pass", new Option("passarg", ""));
			options.AddOption("-e", new Option("encrypt", false));
			options.AddOption("-d", new Option("decrypt", false));
			options.AddOption("-a", new Option("base64", false));
			options.AddOption("-k", new Option("password", ""));
			options.AddOption("-kfile", new Option("kfile", false));
			options.AddOption("-md", new Option("md", ""));
			options.AddOption("-K", new Option("iv", ""));
			options.AddOption("-p", new Option("print", false));
			options.AddOption("-P", new Option("print-exit", false));
			options.AddOption("-bufsize", new Option("bufsize", 0));
			options.AddOption("-engine", new Option("engine", ""));

			// not in usage
			options.AddOption("-salt", new Option("salt", true));
			options.AddOption("-nosalt", new Option("nosalt", false));
			options.AddOption("-debug", new Option("debug", false));
			options.AddOption("-v", new Option("verbose", false));
			options.AddOption("-none", new Option("none", false));

			options.AddMultiOption(Cipher.AllNames, new Option("cipher", true));
		}

		void Usage() {
			Console.Error.WriteLine(
@"options are
-in <file>     input file
-out <file>    output file
-pass <arg>    pass phrase source
-e             encrypt
-d             decrypt
-a/-base64     base64 encode/decode, depending on encryption flag
-k             passphrase is the next argument
-kfile         passphrase is the first line of the file argument
-md            the next argument is the md to use to create a key
                 from a passphrase.  One of md2, md5, sha or sha1
-K/-iv         key/iv in hex is the next argument
-[pP]          print the iv/key (then exit if -P)
-bufsize <n>   buffer size
-engine e      use engine e, possibly a hardware device.
Cipher Types");
			string[] types = Cipher.AllNamesSorted;
			for (int i = 0; i < types.Length; i++) {
				string name = types[i];
				if (name == name.ToUpper())
					continue;

				Console.Error.Write("-{0}", name.PadRight(26));
				if (i % 3 == 0)
					Console.Error.WriteLine();
			}
			Console.Error.WriteLine();
		}

		#region ICommand Members

		public void Execute(string[] args) {
			try {
				options.ParseArguments(args);
			}
			catch (Exception) {
				Usage();
				return;
			}

			MessageDigest md = null;
			if (options.IsSet("md")) {
				md = MessageDigest.CreateByName(options.GetString("md"));
				if (md == null) {
					Console.Error.WriteLine("{0} is an unsupported message digest type", options.GetString("md"));
					return;
				}
			}

			if (md == null)
				md = MessageDigest.MD5;

			if (options.IsSet("bufsize")) {
			}

			BIO bin = Program.GetInFile(options.GetString("infile"));
			string password = null;
			if (options.IsSet("password"))
				password = options.GetString("password");
			else if (options.IsSet("kfile")) {
				string filename = options.GetString("kfile");
				string[] lines = File.ReadAllLines(filename);
				if (lines.Length < 1 || lines[0].Length < 1) {
					Console.Error.WriteLine("zero length password");
					return;
				}
				password = lines[0];
			}

			if (password == null) {
				password = Program.OnPassword(true, options["passarg"]);
				if (password == null) {
					Console.Error.WriteLine("error getting password");
					return;
				}
			}

			if (options.IsSet("base64")) {
			}

			string cipherName = options["cipher"] as string;
			if (!string.IsNullOrEmpty(cipherName)) {
				Cipher cipher = Cipher.CreateByName(cipherName);
				if (cipher == null) {
					Console.Error.WriteLine("{0} is an unknown cipher", cipherName);
					return;
				}

				byte[] salt = null;
				if (!options.IsSet("nosalt")) {
					if (options.IsSet("enc")) {
					}
				}

				byte[] iv;

				CipherContext cc = new CipherContext(cipher);
				if (password != null) {
					byte[] bytes = Encoding.ASCII.GetBytes(password);
					byte[] key = cc.BytesToKey(MessageDigest.MD5, salt, bytes, 1, out iv);
				}
			}

			//string outfile = this.options["outfile"] as string;
			//if (string.IsNullOrEmpty(outfile))
			//    Console.WriteLine(bio.ReadString());
			//else
			//    File.WriteAllText(outfile, bio.ReadString());

		}

		#endregion
	}
}
