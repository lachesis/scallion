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
        public uint WorkGroupSize = 0;
        public uint DeviceId = 0;
        public uint KeySize = 1024;
        public uint ResultsArraySize = 128;
        public Mode ProgramMode = Mode.Normal;
        public string SaveGeneratedKernelPath = null;
        public bool ContinueGeneration = false;
        public string Regex = null;
        public string KeyOutputPath = null;
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
                IntPtr program = context.CreateAndCompileProgram(@"__kernel void get_size() { }");
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
            ProgramParameters parms = ProgramParameters.Instance;
            Func<Mode, Action<string>> parseMode = (m) => (s) => { if (!string.IsNullOrEmpty(s)) { parms.ProgramMode = m; } };
            OptionSet p = new OptionSet()
                .Add<uint>("k|keysize=", "Specify keysize for the RSA key", (i) => parms.KeySize = i)
                .Add("n|nonoptimized", "Run non-optimized kernel", parseMode(Mode.NonOptimized))
                .Add("l|listdevices", "Lists the devices that can be used.", parseMode(Mode.ListDevices))
                .Add("h|?|help", "Display command line usage help.", parseMode(Mode.Help))
                .Add<uint>("d|device=", "Specify the opencl device that should be used.", (i) => parms.DeviceId = i)
                .Add<uint>("g|groupsize=", "Specifies the number of threads in a workgroup.", (i) => parms.WorkGroupSize = i)
                .Add<uint>("w|worksize=", "Specifies the number of hashes preformed at one time.", (i) => parms.WorkSize = i)
                .Add<uint>("t|cputhreads=", "Specifies the number of CPU threads to use when creating work. (EXPERIMENTAL - OpenSSL not thread-safe)", (i) => parms.CpuThreads = i)
                .Add<string>("p|save-kernel=", "Saves the generated kernel to this path.", (i) => parms.SaveGeneratedKernelPath = i)
                .Add<string>("o|output=", "Saves the generated key(s) and address(es) to this path.", (i) => parms.KeyOutputPath = i)
                .Add("c|continue", "When a key is found the program will continue to search for keys rather than exiting.", (i) => { if (!string.IsNullOrEmpty(i)) parms.ContinueGeneration = true; })
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
                        _runtime.Run(ProgramParameters.Instance);
                    }
                    break;
            }

        }

        static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine();
            Console.WriteLine("No delicious scallions for you!!");
            Console.WriteLine("Stopping the GPU and shutting down...");
            Console.WriteLine();
            lock (_runtime) { _runtime.Abort = true; }
            e.Cancel = true;
        }
    }
}
