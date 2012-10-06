using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Runtime.InteropServices;
using OpenSSL.Crypto;
using OpenSSL.Core;
using Mono.Options;

namespace scallion
{
	class Program
	{
		enum Mode
		{
			Normal,
			Help,
			ListDevices
		}
		static void Main(string[] args)
		{
			Mode mode = Mode.Normal;
			Func<Mode, Action<string>> parseMode = (m)=>(s)=>{if(!string.IsNullOrEmpty(s)){mode = m;}};
			OptionSet p = new OptionSet()
			    .Add("h|?|help", parseMode(Mode.Help))
			    .Add("ld|ldevices", parseMode(Mode.ListDevices));
			List<string> extra = p.Parse(args);

			//// Kernel steps
			//// 1. Copy global DER into local space (leave extra bytes)
			//// 2. Increase exponent (using stride) in loop
			//// 3. Hash with SHA1
			//// 4. Get the Onion encoding of this hash
			//// 5. Compare to pattern, if win, quit
			//// Be able to update the exponent size
			//// Watch out for endianness of exponent
		}
	}
}
