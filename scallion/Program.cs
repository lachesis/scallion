using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

using System.Runtime.InteropServices;
using OpenSSL.Crypto;
using OpenSSL.Core;
using System.Reflection;

namespace scallion
{
    class Program
    {
        static void Main(string[] args)
        {
			OpenSSL.Core.ThreadInitialization.InitializeThreads();

			try {
				RSAWrapper rsa = new RSAWrapper();
				rsa.GenerateKey(1024, 65537);
				rsa.CheckSanity();

				string hostname = rsa.OnionHash + ".onion";
				string pem = rsa.Rsa.PrivateKeyAsPEM;

				System.IO.File.WriteAllText("hostname", hostname);
				System.IO.File.WriteAllText("private_key", pem);

				Shutdown(0);
			} 
			catch {
				Shutdown(1);
			}
        }

		public static void Shutdown(int code = 0)
		{
			OpenSSL.Core.ThreadInitialization.UninitializeThreads();
			Environment.ExitCode = code;
		}

        static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
			Shutdown();
            e.Cancel = true;
        }
    }
}
