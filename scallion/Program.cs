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
			NonOptimized,
			Help,
			ListDevices
		}

		public static void ListDevices()
		{
			int deviceId = 0;
			foreach (CLDeviceInfo device in CLRuntime.GetDevices())
			{
				if (!device.CompilerAvailable) continue;
				//get preferredWorkGroupSize
				ulong preferredWorkGroupSize;
				{
					CLContext context = new CLContext(device.DeviceId);
					IntPtr program = context.CreateAndCompileProgram(
						System.IO.File.ReadAllText(
							System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + System.IO.Path.DirectorySeparatorChar + "kernel.cl"
						)
					);
					CLKernel kernel = context.CreateKernel(program, "shasearch");
					preferredWorkGroupSize = kernel.KernelPreferredWorkGroupSizeMultiple;
					kernel.Dispose();
					OpenTK.Compute.CL10.CL.ReleaseProgram(program);
					context.Dispose();
				}
				//display device
				Console.WriteLine("Id:{0} Name:{1}",
					deviceId, device.Name.Trim());
				Console.WriteLine("    PreferredGroupSizeMultiple:{0} ComputeUnits:{1} ClockFrequency:{2}",
					preferredWorkGroupSize, device.MaxComputeUnits, device.MaxClockFrequency);
				Console.WriteLine("");
				deviceId++;
			}
		}
		public static void Help(OptionSet p)
		{
			Console.WriteLine("Usage: scallion [OPTIONS]+ prefix suffix");
			Console.WriteLine("Searches for a tor hidden service address that starts with the provided prefix and ends with the provided suffix.");
			Console.WriteLine();
			Console.WriteLine("Options:");
			p.WriteOptionDescriptions(Console.Out);
		}
		static CLRuntime _runtime = new CLRuntime();
		static void Main(string[] args)
		{
			Mode mode = Mode.Normal;
			int deviceId = 0;
			int workGroupSize = 512;
			int workSize = 1024 * 1024 * 16;
			Func<Mode, Action<string>> parseMode = (m) => (s) => { if (!string.IsNullOrEmpty(s)) { mode = m; } };
			OptionSet p = new OptionSet()
				.Add("o|notoptimized", "Runs program using the kernel that is not optimized.", parseMode(Mode.NonOptimized))
				.Add("l|listdevices", "Lists the devices that can be used.", parseMode(Mode.ListDevices))
				.Add("h|?|help", "Display command line usage help.", parseMode(Mode.Help))
				.Add<int>("d|device=", "Specify the opencl device that should be used.", (i) => deviceId = i)
				.Add<int>("g|groupsize=", "Specifics the number of threads in a workgroup.", (i) => workGroupSize = i)
				.Add<int>("w|worksize=", "Specifies the number of hashes preformed at one time.", (i) => workSize = i);
			List<string> extra = p.Parse(args);
			if (mode == Mode.NonOptimized || mode == Mode.Normal)
			{
				if (extra.Count < 1) mode = Mode.Help;
				else if (extra.Count < 2) extra.Add("");
			}
			switch (mode)
			{
				case Mode.Help:
					Help(p);
					break;
				case Mode.ListDevices:
					ListDevices();
					break;
				case Mode.Normal:
					{
						Console.CancelKeyPress += new ConsoleCancelEventHandler(Console_CancelKeyPress);
						_runtime.Run(deviceId, workGroupSize, workSize, "kernel.cl", extra[0], extra[1]);
					}
					break;
				case Mode.NonOptimized:
					{
						Console.CancelKeyPress += new ConsoleCancelEventHandler(Console_CancelKeyPress);
						_runtime.Run(deviceId, workGroupSize, workSize, "kernel.cl", extra[0], extra[1]);
					}
					break;
			}

		}

		static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
		{
			Console.WriteLine();
			Console.WriteLine("No delicions scallions for you!!");
			Console.WriteLine("Stopping the GPU and shutting down...");
			Console.WriteLine();
			lock (_runtime) { _runtime.Abort = true; }
			e.Cancel = true;
		}
	}
}
