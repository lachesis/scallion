using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Runtime.InteropServices;
using OpenSSL.Crypto;
using OpenSSL.Core;
using Mono.Options;
using System.Reflection;

namespace scallion
{
	public enum Mode
	{
		Normal,
		NonOptimized,
		Help,
		ListDevices
	}

	public class ProgramParameters
	{
		private static ProgramParameters _instance = new ProgramParameters();
		public static ProgramParameters Instance
		{
			get { return _instance; }
		}
		public uint CpuThreads = 1;
		public uint WorkSize = 1024 * 1024 * 16;
		public uint WorkGroupSize = 512;
		public uint DeviceId = 0;
		public uint KeySize = 1024;
		public Mode ProgramMode = Mode.Normal;
		public KernelType KernelType
		{
			get
			{
				if (ProgramMode == Mode.NonOptimized) 
					return KernelType.Normal;
				switch (KeySize)
				{
					case 4096:
					case 2048:
						return KernelType.Optimized4_11;
					case 1024:
						return KernelType.Optimized4_9;
				}
				throw new System.NotImplementedException();
			}
		}
		public string CreateDefinesString()
		{
			StringBuilder builder = new StringBuilder();
			FieldInfo[] fields = this.GetType()
				.GetFields(BindingFlags.Public | BindingFlags.Instance);
			foreach (FieldInfo field in fields)
			{
				object value = field.GetValue(this);
				if (value.GetType() == typeof(uint))
					builder.AppendLine(string.Format("#define {0} {1}", field.Name, value));
			}
			return builder.ToString();
		}
	}

	class Program
	{


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
					IntPtr program = context.CreateAndCompileProgram(@"__kernel void get_size() { }");
					CLKernel kernel = context.CreateKernel(program, "get_size");
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
				Console.WriteLine("    MaxConstantBufferSize:{0} MaxConstantArgs:{1} MaxMemAllocSize:{2}",
				    device.MaxConstantBufferSize, device.MaxConstantArgs, device.MaxMemAllocSize);
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
			ProgramParameters parms = ProgramParameters.Instance;
			Func<Mode, Action<string>> parseMode = (m) => (s) => { if (!string.IsNullOrEmpty(s)) { parms.ProgramMode = m; } };
			OptionSet p = new OptionSet()
				.Add<uint>("k|keysize=", "Specify keysize for the RSA key", (i) => parms.KeySize = i)
				.Add("n|nonoptimized", "Run non-optimized kernel", parseMode(Mode.NonOptimized))
				.Add("l|listdevices", "Lists the devices that can be used.", parseMode(Mode.ListDevices))
				.Add("h|?|help", "Display command line usage help.", parseMode(Mode.Help))
				.Add<uint>("d|device=", "Specify the opencl device that should be used.", (i) => parms.DeviceId = i)
				.Add<uint>("g|groupsize=", "Specifics the number of threads in a workgroup.", (i) => parms.WorkGroupSize = i)
				.Add<uint>("w|worksize=", "Specifies the number of hashes preformed at one time.", (i) => parms.WorkSize = i)
				.Add<uint>("t|cputhreads=", "Specifies the number of CPU threads to use when creating work. (EXPERIMENTAL - OpenSSL not thread-safe)", (i) => parms.CpuThreads = i);
				
			List<string> extra = p.Parse(args);
			if (parms.ProgramMode == Mode.NonOptimized || parms.ProgramMode == Mode.Normal)
			{
				if (extra.Count < 1) parms.ProgramMode = Mode.Help;
				else if (extra.Count < 2) extra.Add("");
			}

			//_runtime.Run(ProgramParameters.Instance,"tron[2345]");
			switch (parms.ProgramMode)
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
						_runtime.Run(ProgramParameters.Instance,extra[0]);
					}
					break;
				case Mode.NonOptimized:
					{
						Console.CancelKeyPress += new ConsoleCancelEventHandler(Console_CancelKeyPress);
						_runtime.Run(ProgramParameters.Instance,extra[0]);
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
