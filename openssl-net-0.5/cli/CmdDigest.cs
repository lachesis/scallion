using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL.Crypto;

namespace OpenSSL.CLI 
{
	class CmdDigest : ICommand
	{
		OptionParser options = new OptionParser();

		public CmdDigest() 
		{
		}

		void Usage() {
			Console.Error.WriteLine(
@"options are
-c              to output the digest with separating colons
-d              to output debug info
-hex            output as hex dump
-binary         output in binary form
-sign   file    sign digest using private key in file
-verify file    verify a signature using public key in file
-prverify file  verify a signature using private key in file
-keyform arg    key file format (PEM or ENGINE)
-signature file signature to verify
-binary         output in binary form
-engine e       use engine e, possibly a hardware device.
Message Digest Types");
			string[] types = MessageDigest.AllNamesSorted;
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

		public void Execute(string[] args) 
		{
			Usage();
		}

		#endregion
	}
}
