using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

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
        public uint WorkGroupSize = 0;
        public uint DeviceId = 0;
        public uint KeySize = 1024;
        public uint ResultsArraySize = 128;
        public Mode ProgramMode = Mode.Normal;
        public string SaveGeneratedKernelPath = null;
        public bool ContinueGeneration = false;
        public string Regex = null;
        public string KeyOutputPath = null;
        public string Command = null;
        
        public uint UnixTs = 0;

		public bool SkipShaTest = false;
		public uint QuitAfterXKeysFound = 0;

		public bool GPGMode = false;

		public ToolConfig ToolConfig = null;

		public int ExponentIndex {
			get {
				if (GPGMode) {
					switch (KeySize) {
					case 8192:
					case 4096:
					case 2048:
					case 1024:
						return 13;
					case 3192:
						return 28;
					default:
						throw new System.NotImplementedException();
					}
				}
				else {
					switch (KeySize) {
					case 4096:
					case 2048:
						return 11;
					case 1024:
						return 9;
					default:
						throw new System.NotImplementedException();
					}
				}
			}
		}

		public KernelType KernelType
        {
            get
            {
                if (ProgramMode == Mode.NonOptimized)
                    return KernelType.Normal;
				else
					return KernelType.Optimized4;
            }
        }

		/// <summary>
		/// Reflect every uint or KernelType into the #defines of the kernel.
		/// </summary>
		/// <returns>The defines string.</returns>
        public string CreateDefinesString()
        {
            StringBuilder builder = new StringBuilder();
            var fields = this.GetType()
                .GetFields(BindingFlags.Public | BindingFlags.Instance)
                .Cast<object>()
                .Concat(this.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance).Cast<object>());
            foreach (var field in fields)
            {
                KeyValuePair<string, object> value = new KeyValuePair<string, object>();
                if (field as FieldInfo != null)
                    value = new KeyValuePair<string, object>(((FieldInfo)field).Name, ((FieldInfo)field).GetValue(this));
                else if (field as PropertyInfo != null)
                    value = new KeyValuePair<string, object>(((PropertyInfo)field).Name, ((PropertyInfo)field).GetValue(this, null));
                if (value.Value == null) continue;
                if (value.Value.GetType() == typeof(uint))
                    builder.AppendLine(string.Format("#define {0} {1}", value.Key, value.Value));
                if (value.Value.GetType() == typeof(KernelType))
                    builder.AppendLine(string.Format("#define KT_{0}", value.Value));
            }
            return builder.ToString();
        }
    }

    class Program
    {
        // returns the queried preferred work group size for a device
        // moved to external function as we call it also in Main
        public static ulong getPreferredWorkGroupSize(IntPtr deviceId)
        {
            //get preferredWorkGroupSize
            ulong preferredWorkGroupSize;
            {
                CLContext context = new CLContext(deviceId);
                IntPtr program = context.CreateAndCompileProgram(@"__kernel void get_size(__global float2 *in) { }");
                CLKernel kernel = context.CreateKernel(program, "get_size");
                preferredWorkGroupSize = kernel.KernelPreferredWorkGroupSizeMultiple;
                kernel.Dispose();
                OpenTK.Compute.CL10.CL.ReleaseProgram(program);
                context.Dispose();
            }
            return preferredWorkGroupSize;
        }

        public static void ListDevices()
        {
            int deviceId = 0;
            foreach (CLDeviceInfo device in CLRuntime.GetDevices())
            {
                if (!device.CompilerAvailable) continue;
                //get preferredWorkGroupSize
                ulong preferredWorkGroupSize = getPreferredWorkGroupSize(device.DeviceId);  // moved to external function as we call it also in Main

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
            Console.WriteLine("Usage: scallion [OPTIONS]+ regex [regex]+");
            Console.WriteLine("Searches for a tor hidden service address that matches one of the provided regexes.");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }
        static CLRuntime _runtime = new CLRuntime();
        static void Main(string[] args)
        {
			OpenSSL.Core.ThreadInitialization.InitializeThreads();

			//Console.WriteLine("{0:x}",TorBase32.FromBase32Str("77777777")[0]);
			//Console.WriteLine("{0:x}",TorBase32.FromBase32Str("aaaaaaaa")[0]);

			// TODO: Clean up gpg fingerprint test and move it elsewhere
			/*RSAWrapper r = new RSAWrapper();
			r.Timestamp = 1387430955;
			r.Rsa.PublicModulus = BigNumber.FromHexString("00E2FC646FF48AFC8C2A7DDF1B99CECD21A0AEC603DBAAA1A7ADF6836A6CED82BAE694AC5A4ACBD7FC1D36B2C677BE25E400330D295D044C9F6AFAEA45A8CF370F59E398F853FFCED03395D297CEED47C0E9EF2C358C05399E1F8A878E6E044F1AB7D82A162C77EE956B0A9B54C910000EF7122CC8BBB1746872968F05E7CFD563");
			r.Rsa.PublicExponent = 0x010001;
			Console.WriteLine("GPG Fingerprint: {0}", r.GPG_fingerprint_string);*/

            ProgramParameters parms = ProgramParameters.Instance;
            Func<Mode, Action<string>> parseMode = (m) => (s) => { if (!string.IsNullOrEmpty(s)) { parms.ProgramMode = m; } };
            OptionSet p = new OptionSet()
                .Add<uint>("k|keysize=", "Specifies keysize for the RSA key", (i) => parms.KeySize = i)
                .Add("n|nonoptimized", "Runs non-optimized kernel", parseMode(Mode.NonOptimized))
                .Add("l|listdevices", "Lists the devices that can be used.", parseMode(Mode.ListDevices))
                .Add("h|?|help", "Displays command line usage help.", parseMode(Mode.Help))
				.Add("gpg", "GPG vanitygen mode.", (i) => { if (!string.IsNullOrEmpty(i)) parms.GPGMode = true; })
                .Add<uint>("d|device=", "Specifies the opencl device that should be used.", (i) => parms.DeviceId = i)
                .Add<uint>("g|groupsize=", "Specifies the number of threads in a workgroup.", (i) => parms.WorkGroupSize = i)
                .Add<uint>("w|worksize=", "Specifies the number of hashes preformed at one time.", (i) => parms.WorkSize = i)
                .Add<uint>("t|cputhreads=", "Specifies the number of CPU threads to use when creating work. (EXPERIMENTAL - OpenSSL not thread-safe)", (i) => parms.CpuThreads = i)
				.Add<string>("p|save-kernel=", "Saves the generated kernel to this path.", (i) => parms.SaveGeneratedKernelPath = i)
                .Add<string>("o|output=", "Saves the generated key(s) and address(es) to this path.", (i) => parms.KeyOutputPath = i)
				.Add("skip-sha-test", "Skip the SHA-1 test at startup.", (i) => { if (!string.IsNullOrEmpty(i)) parms.SkipShaTest = true; })
				.Add<uint>("quit-after=", "Quit after this many keys have been found.", (i) => parms.QuitAfterXKeysFound = i)
				.Add<uint>("timestamp=", "Use this value as a timestamp for the RSA key.", (i) => parms.UnixTs = i)
                .Add("c|continue", "Continue to search for keys rather than exiting when a key is found.", (i) => { if (!string.IsNullOrEmpty(i)) parms.ContinueGeneration = true; })
                .Add<string>("command=", "When a match is found specified external program is called with key passed to stdin.\nExample: \"--command 'tee example.txt'\" would save the key to example.txt\nIf the command returns with a non-zero exit code, the program will return the same code.", (i) => parms.Command = i)
                ;

            List<string> extra = p.Parse(args);

            if (parms.ProgramMode == Mode.NonOptimized || parms.ProgramMode == Mode.Normal)
            {
                if (extra.Count < 1) parms.ProgramMode = Mode.Help;
                else parms.Regex = extra.ToDelimitedString("|");
            }

            //_runtime.Run(ProgramParameters.Instance,"prefix[abcdef]");
            switch (parms.ProgramMode)
            {
                case Mode.Help:
                    Help(p);
                    break;
                case Mode.ListDevices:
                    ListDevices();
                    break;
                case Mode.Normal:
		        case Mode.NonOptimized:
		            {
		                // If no Work Group Size provided, then query the selected device for preferred, if not found set to 32.
		                if (parms.WorkGroupSize == 0)
		                {
		                    ulong preferredWorkGroupSize = 32;
		                    uint deviceId = 0;
		                    foreach (CLDeviceInfo device in CLRuntime.GetDevices())
		                    {
		                        if (!device.CompilerAvailable) continue;
		                        if (deviceId == parms.DeviceId)
		                        {
		                            preferredWorkGroupSize = getPreferredWorkGroupSize(device.DeviceId);
		                            break;
		                        }
		                        deviceId++;
		                    }

		                    parms.WorkGroupSize = (uint)preferredWorkGroupSize;
		                }
						
		                Console.CancelKeyPress += new ConsoleCancelEventHandler(Console_CancelKeyPress);
						try {
		                	_runtime.Run(ProgramParameters.Instance);
						}
						finally {
							Shutdown();
						}
		            }
            break;
            }

        }

		public static void Shutdown(int code = 0)
		{
			// Don't try to shutdown twice
			lock (_runtime) { 
				if (_runtime.Abort) {
					return;
				}
			}

			ProgramParameters parms = ProgramParameters.Instance;
			Console.WriteLine();
			Console.WriteLine("Stopping the GPU and shutting down...");
			Console.WriteLine();
			lock (_runtime) { _runtime.Abort = true; }
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
