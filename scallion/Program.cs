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
		public static List<CLDeviceInfo> GetDevices()
		{
			return CLDeviceInfo.GetDeviceIds()
				.Select(i => new CLDeviceInfo(i))
				.Where(i => i.CompilerAvailable)
				.ToList();
		}
		public static void ListDevices()
		{
			int deviceId = 0;
			foreach (CLDeviceInfo device in GetDevices())
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
				.Add("d|device", (i) => { if (!string.IsNullOrEmpty(i)) { deviceId = int.Parse(i); } });
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
			
			CLDeviceInfo device = GetDevices()[deviceId];
			CLContext context = new CLContext(device.DeviceId);
			IntPtr program = context.CreateAndCompileProgram(@"
__kernel void hello(__global char* message, int j){
message[0] = 'H';
message[1] = 'e';
message[2] = 'l';
message[3] = 'l';
message[4] = 'o';
message[5] = ',';
message[6] = ' ';
message[7] = 'W';
message[8] = 'o';
message[9] = 'r';
message[10] = 'l';
message[11] = 'd';
message[12] = '!';
message[13] = '\0';
}
");
			CLKernel kernel = context.CreateKernel(program, "hello");

			byte[] message = new byte[14];
			CLBuffer<byte> buf = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadWrite | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, message);

			buf.EnqueueWrite();
			kernel.SetKernelArg(0, buf);
			kernel.SetKernelArg(1, 1);

			kernel.EnqueueNDRangeKernel(1024 * 1024, 128);
			ulong j = kernel.KernelPreferredWorkGroupSizeMultiple;

			buf.EnqueueRead();

			Console.WriteLine(BitConverter.ToString(message));

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
