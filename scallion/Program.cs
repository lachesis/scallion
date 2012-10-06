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

			IntPtr devid = CLDeviceInfo.GetDeviceIds()[0];
			CLContext context = new CLContext(devid);
			IntPtr program = context.CreateAndCompileProgram(@"
__kernel void hello(__global char* message){
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
			CLKernel kernel = context.CreateKernel(program,"hello");

			byte[] message = new byte[14];
			CLBuffer<byte> buf = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadWrite | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr,message);

			buf.EnqueueWrite();
			kernel.SetKernelArg(0,buf);

			kernel.EnqueueNDRangeKernel();

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
