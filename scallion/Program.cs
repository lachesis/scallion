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

		public static void ListDevices()
		{
			int deviceId = 0;
			foreach (CLDeviceInfo device in CLRuntime.GetDevices())
			{
				if (!device.CompilerAvailable) continue;
				Console.WriteLine("Id:{0} Name:{1}", deviceId, device.Name.Trim());
				deviceId++;
			}
		}
		public static void Help()
		{
		}

		static void Main(string[] args)
		{
			Mode mode = Mode.Normal;
			int deviceId = 0;
			Func<Mode, Action<string>> parseMode = (m) => (s) => { if (!string.IsNullOrEmpty(s)) { mode = m; } };
			OptionSet p = new OptionSet()
				.Add("h|?|help", parseMode(Mode.Help))
				.Add("ld|ldevice", parseMode(Mode.ListDevices))
				.Add("d|device=", (i) => { if (!string.IsNullOrEmpty(i)) { deviceId = int.Parse(i); } });
			List<string> extra = p.Parse(args);

			switch (mode)
			{
				case Mode.Help:
					Help();
					break;
				case Mode.ListDevices:
					ListDevices();
					break;
			}

			CLRuntime runtime = new CLRuntime();
			runtime.Run(deviceId, 128, 1024 * 1024 * 16);
		}
	}
}
