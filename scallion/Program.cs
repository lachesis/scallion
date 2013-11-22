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
        ListDevices,
		WriteModuli,
		ReadResults
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

		public string RSAModuliPath = null;
		public string InputResultsPath = null;

		public Queue<BigNumber> RSAPublicModuli = null;
		public StreamWriter UsedModuliFile = null;

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

		public static void WriteModuli()
		{
			ProgramParameters parms = ProgramParameters.Instance;

			var rp = new RegexPattern(parms.Regex);
			ulong hashes_per_win = (ulong)(0.5 / rp.GenerateAllOnionPatternsForRegex().Select(t=>Math.Pow(2,-5*t.Count(q=>q!='.'))).Sum());
			ulong hashes_per_key = (CLRuntime.EXP_MAX - CLRuntime.EXP_MIN) / 2;
			ulong keys_needed = hashes_per_win / hashes_per_key;
			uint SF = 5;

			Console.WriteLine("Generating that pattern will require approximately {0:0.000} gigahashes.", hashes_per_win / 1e9);
			Console.WriteLine("That will require on average {0} public keys.", keys_needed);
			Console.WriteLine("Generating {0} keys (for safety's sake).", keys_needed * SF);

			RSAWrapper rsa = new RSAWrapper();

			StreamWriter priv_sw = new StreamWriter(parms.RSAModuliPath + ".priv");
			StreamWriter pub_sw = new StreamWriter(parms.RSAModuliPath);
			for (ulong i = 0; i < keys_needed * SF; i++)
			{
				if (i % 100 == 0) {
					Console.WriteLine("Generating key {0} of {1}...", i, keys_needed*SF);
				}
				rsa.GenerateKey((int)parms.KeySize);
				pub_sw.WriteLine(rsa.Rsa.PublicModulus.ToDecimalString());
				priv_sw.WriteLine("Public Modulus: " + rsa.Rsa.PublicModulus.ToDecimalString());
				priv_sw.WriteLine(rsa.Rsa.PrivateKeyAsPEM);
				priv_sw.WriteLine("");
			}
			pub_sw.Close();
			priv_sw.Close();
		}

		public static void ReadResults()
		{
			ProgramParameters parms = ProgramParameters.Instance;

			string rsaPrivFn = parms.RSAModuliPath + ".priv";
			if (!File.Exists(rsaPrivFn)) {
				Console.WriteLine("Error: expecting private key file at {0}.", rsaPrivFn);
				return;
			}
			if (!File.Exists(parms.InputResultsPath)) {
				Console.WriteLine("Error: expecting results from miner at {0}.", parms.InputResultsPath);
				return;
			}

			// Create a map to hold (public modulus as decimal string) -> (private key as pem)
			IDictionary<string, string> modulusKeyMap = new Dictionary<string, string>();

			// Read the priv key list file
			string currentModulus = null, currentPEM = null;
			foreach (string l in File.ReadAllLines(rsaPrivFn)) {
				string line = l.Trim();
				if (line.StartsWith("Public Modulus: ")) {
					currentModulus = line.Replace("Public Modulus: ","");
				}

				if (line.StartsWith("-----BEGIN RSA PRIVATE KEY-----")) {
					currentPEM = "";
				}
				currentPEM += line + "\n";
				if (line.StartsWith("-----END RSA PRIVATE KEY-----")) {
					modulusKeyMap.Add(currentModulus, currentPEM);
				}
			}

			// Read the results file
			string modulus = null, exponent = null, address = null;
			foreach (string l in File.ReadAllLines(parms.InputResultsPath))	{
				//string[] split = l.Trim().Split(":".ToCharArray(), 2);
				string line = l.Trim();
				if (line.StartsWith("Public Modulus: ")) {
					modulus = line.Replace("Public Modulus: ","");
				}
				if (line.StartsWith("Public Exponent: ")) {
					exponent = line.Replace("Public Exponent: ","");
				}
				if (line.StartsWith("Address/Hash: ")) {
					address = line.Replace("Address/Hash: ","");
				}

				if (modulus != null && exponent != null && address != null) {
					// Find the modulus in the private key map
					string pem;
					if (!modulusKeyMap.TryGetValue(modulus, out pem)) {
						throw new InvalidDataException(String.Format("Modulus {0} is missing from the private key data file.", modulus));
					}

					// Load the PEM into the RSA
					RSAWrapper rsa = new RSAWrapper();
					rsa.FromPrivateKeyPEM(pem);

					// Verify that modulus matches
					if (rsa.Rsa.PublicModulus != BigNumber.FromDecimalString(modulus)) {
						throw new InvalidDataException("Modulus of PEM does not match declared value.");
					}

					// Change the public exponent
					rsa.ChangePublicExponent(BigNumber.FromDecimalString(exponent));

					// Check the key's sanity
					rsa.CheckSanity();

					// Verify the hash
					if (rsa.OnionHash + ".onion" != address) {
						throw new InvalidDataException("Onion hash of key does not match declared value.");
					}

					// Yay the key is good! Output it as required
					CLRuntime.OutputKey(rsa);

					modulus = null;
					exponent = null;
					address = null;
				}

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
                .Add<uint>("k|keysize=", "Specifies keysize for the RSA key", (i) => parms.KeySize = i)
                .Add("n|nonoptimized", "Runs non-optimized kernel", parseMode(Mode.NonOptimized))
                .Add("l|listdevices", "Lists the devices that can be used.", parseMode(Mode.ListDevices))
                .Add("h|?|help", "Displays command line usage help.", parseMode(Mode.Help))
                .Add<uint>("d|device=", "Specifies the opencl device that should be used.", (i) => parms.DeviceId = i)
                .Add<uint>("g|groupsize=", "Specifies the number of threads in a workgroup.", (i) => parms.WorkGroupSize = i)
                .Add<uint>("w|worksize=", "Specifies the number of hashes preformed at one time.", (i) => parms.WorkSize = i)
                .Add<uint>("t|cputhreads=", "Specifies the number of CPU threads to use when creating work. (EXPERIMENTAL - OpenSSL not thread-safe)", (i) => parms.CpuThreads = i)
				.Add<string>("m|modulifile=", "Specifies a file containing public key moduli", (i) => parms.RSAModuliPath = i)
				.Add("s|write-moduli", "Writes moduli and private keys for a given pattern to the file specified with -m", (i) => { if (parms.ProgramMode != Mode.Help) parms.ProgramMode = Mode.WriteModuli; })
				.Add("r|read-results=", "Reads a results file (generated by a remote miner) and output the winning key (-m must be specified)", (i) => parms.InputResultsPath = i)
				.Add<string>("p|save-kernel=", "Saves the generated kernel to this path.", (i) => parms.SaveGeneratedKernelPath = i)
                .Add<string>("o|output=", "Saves the generated key(s) and address(es) to this path.", (i) => parms.KeyOutputPath = i)
                .Add("c|continue", "Continue to search for keys rather than exiting when a key is found.", (i) => { if (!string.IsNullOrEmpty(i)) parms.ContinueGeneration = true; })
                ;

            List<string> extra = p.Parse(args);

			if (parms.InputResultsPath != null && parms.ProgramMode != Mode.Help) {
				parms.ProgramMode = Mode.ReadResults;
			}

            if (parms.ProgramMode == Mode.NonOptimized || parms.ProgramMode == Mode.Normal || parms.ProgramMode == Mode.WriteModuli)
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
				case Mode.WriteModuli:
					WriteModuli();
					break;
				case Mode.ReadResults:
					ReadResults();
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

						// If a moduli file is specified, read it and create or read a .used file
						if (parms.RSAModuliPath != null)
						{
							if (File.Exists(parms.RSAModuliPath))
							{
								// Read and/or create used file
								string usedPath = parms.RSAModuliPath + ".used";
								HashSet<string> used = null;
								if (File.Exists(usedPath))
								{
									used = new HashSet<string>();
									foreach (var line in File.ReadAllLines(usedPath))
									{
										used.Add(line.Trim());
									}
								}
								else
								{
									File.WriteAllText(usedPath, "");
								}

								// Set up used file to be written later
								parms.UsedModuliFile = new StreamWriter(usedPath, true);

								// Read moduli file
								parms.RSAPublicModuli = new Queue<BigNumber>();
								foreach (var line in File.ReadAllLines(parms.RSAModuliPath))
								{
									if (used == null || !used.Contains(line.Trim()))
										parms.RSAPublicModuli.Enqueue(BigNumber.FromDecimalString(line.Trim()));
								}
							}
						}

		                Console.CancelKeyPress += new ConsoleCancelEventHandler(Console_CancelKeyPress);
		                _runtime.Run(ProgramParameters.Instance);
		            }
            break;
            }

        }

        static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
			ProgramParameters parms = ProgramParameters.Instance;
			if (parms.UsedModuliFile != null)
				parms.UsedModuliFile.Close();
            Console.WriteLine();
            Console.WriteLine("No delicious scallions for you!!");
            Console.WriteLine("Stopping the GPU and shutting down...");
            Console.WriteLine();
            lock (_runtime) { _runtime.Abort = true; }
            e.Cancel = true;
        }
    }
}
