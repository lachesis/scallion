using System;
using System.Linq;
using System.Collections.Generic;
using OpenSSL.Core;
using OpenSSL.Crypto;
using System.Threading;

namespace scallion
{
	public class CLRuntime
	{
		public static List<CLDeviceInfo> GetDevices()
		{
			return CLDeviceInfo.GetDeviceIds()
				.Select(i => new CLDeviceInfo(i))
				.Where(i => i.CompilerAvailable)
				.ToList();
		}

		static private int get_der_len(ulong val)
		{
			if(val == 0) return 1;
			ulong tmp = val;
			int len = 0;

			// Find the length of the value
			while(tmp != 0) {
				tmp >>= 8;
				len++;
			}

			// if the top bit of the number is set, we need to prepend 0x00
			if(((val >> 8*(len-1)) & 0x80) == 0x80)
				len++;

			return len;
		}
		
		public class KernelInput
		{
			public KernelInput(int num_exps)
			{
				Rsa = new RSAWrapper();
				LastWs = new uint[num_exps * 16];
				Midstates = new uint[num_exps * 5];
				ExpIndexes = new int[num_exps];
				Results = new uint[128];
			}
			public readonly uint[] LastWs;
			public readonly uint[] Midstates;
			public readonly int[] ExpIndexes;
			public readonly RSAWrapper Rsa;
			public readonly uint[] Results;
		}
		const ulong EXP_MIN = 0x01010001;
		const ulong EXP_MAX = 0x7FFFFFFF;
		public bool Abort = false;
		private Queue<KernelInput> _kernelInput = new Queue<KernelInput>();
		private void CreateInput()
		{
			while (true)
			{
				bool inputQueueIsLow = false;
				lock (_kernelInput)	{ inputQueueIsLow = _kernelInput.Count < 30; }
				if (inputQueueIsLow)
				{
					int num_exps = (get_der_len(EXP_MAX) - get_der_len(EXP_MIN) + 1);
					KernelInput input = new KernelInput(num_exps);

					profiler.StartRegion("generate key");
					input.Rsa.GenerateKey(1024); // Generate a key
					profiler.EndRegion("generate key");

					// Build DERs and calculate midstates for exponents of representitive lengths
					profiler.StartRegion("cpu precompute");
					int cur_exp_num = 0;
					BigNumber[] Exps = new BigNumber[num_exps];
					for (int i = get_der_len(EXP_MIN); i <= get_der_len(EXP_MAX); i++)
					{
						ulong exp = (ulong)0x01 << (int)((i - 1) * 8);

						// Set the exponent in the RSA key
						// NO SANITY CHECK - just for building a DER
						input.Rsa.Rsa.PublicExponent = (BigNumber)exp;
						Exps[cur_exp_num] = (BigNumber)exp;

						// Get the DER
						byte[] der = input.Rsa.DER;
						int exp_index = der.Length % 64 - i;

						// Put the DER into Ws
						SHA1 Sha1 = new SHA1();
						List<uint[]> Ws = Sha1.DataToPaddedBlocks(der);

						// Put all but the last block through the hash
						Ws.Take(Ws.Count - 1).Select((t) =>
						{
							Sha1.SHA1_Block(t);
							return t;
						}).ToArray();

						// Put the midstate, the last W block, and the byte index of the exponent into the CL buffers
						Sha1.H.CopyTo(input.Midstates, 5 * cur_exp_num);
						Ws.Last().Take(16).ToArray().CopyTo(input.LastWs, 16 * cur_exp_num);
						input.ExpIndexes[cur_exp_num] = exp_index;

						// Increment the current exponent size
						cur_exp_num++;
						break;
					}
					profiler.EndRegion("cpu precompute");
					lock (_kernelInput) { _kernelInput.Enqueue(input); } //put input on queue
					continue;//skip the sleep cause we might be really low
				}
				Thread.Sleep(50);
			}
		}

		private TimeSpan PredictedRuntime(string prefix, string suffix, long speed)
		{
			int len = prefix.Length + suffix.Length;
			long runtime_sec = (long)Math.Pow(2,5*len-1) / speed;
			int days=(int)(runtime_sec/86400), hrs=(int)((runtime_sec%86400)/3600), min=(int)(runtime_sec%3600)/60, sec=(int)(runtime_sec%60);
			TimeSpan ts = new TimeSpan(days,hrs,min,sec);
			return ts;
		}

		private Profiler profiler = null;
		public void Run(int deviceId, int workGroupSize, int workSize, string kernelFileName, string kernelName, string prefix, string suffix)
		{
			Console.WriteLine("Cooking up some delicions scallions...");
			profiler = new Profiler();
			#region init
			profiler.StartRegion("init");
			//create device context and kernel
			CLDeviceInfo device = GetDevices()[deviceId];
			CLContext context = new CLContext(device.DeviceId);
			IntPtr program = context.CreateAndCompileProgram(
				System.IO.File.ReadAllText(
					System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + System.IO.Path.DirectorySeparatorChar + kernelFileName
				)
			);

			// TODO: Make sure to check optimized kernel constraints somewhere

			CLKernel kernel = context.CreateKernel(program, kernelName);
			//Create buffers
			CLBuffer<uint> bufLastWs;
			CLBuffer<uint> bufMidstates;
			CLBuffer<int> bufExpIndexes;
			CLBuffer<uint> bufResults;
			{
				int num_exps = (get_der_len(EXP_MAX) - get_der_len(EXP_MIN) + 1);
				uint[] LastWs = new uint[num_exps * 16];
				uint[] Midstates = new uint[num_exps * 5];
				int[] ExpIndexes = new int[num_exps];
				uint[] Results = new uint[128];

				bufLastWs = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, LastWs);
				bufMidstates = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Midstates);
				bufExpIndexes = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, ExpIndexes);
				bufResults = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadWrite | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Results);
			}
			//Create pattern buffers
			CLBuffer<uint> bufPattern;
			CLBuffer<uint> bufBitmask;
			{
				string patternStr = prefix + "".PadLeft(16 - prefix.Length - suffix.Length, 'a') + suffix;
				uint[] Pattern = TorBase32.ToUIntArray(TorBase32.FromBase32Str(patternStr));
				string bitmaskStr = "".PadLeft(prefix.Length, 'x') + "".PadLeft(16 - prefix.Length - suffix.Length, '_') + "".PadLeft(suffix.Length, 'x');
				uint[] Bitmask = TorBase32.ToUIntArray(TorBase32.CreateBase32Mask(bitmaskStr));
				bufPattern = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Pattern);
				bufBitmask = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Bitmask);
			}
			//Set kernel arguments
			lock (new object()) { } // Empty lock, resolves (or maybe hides) a race condition in SetKernelArg
			kernel.SetKernelArg(0, bufLastWs);
			kernel.SetKernelArg(1, bufMidstates);
			kernel.SetKernelArg(2, bufExpIndexes);
			kernel.SetKernelArg(3, bufResults);
			kernel.SetKernelArg(4, EXP_MIN);
			kernel.SetKernelArg(5, (byte)get_der_len(EXP_MIN));
			kernel.SetKernelArg(6, bufPattern);
			kernel.SetKernelArg(7, bufBitmask);
			profiler.EndRegion("init");

			//start the thread to generate input data
			Thread inputThread = new Thread(CreateInput);
			inputThread.Start();
			Thread.Sleep(3000);//wait just a bit so some work is available
			#endregion

			int loop = 0;

			var gpu_runtime_sw = System.Diagnostics.Stopwatch.StartNew();

			profiler.StartRegion("total without init");
			bool success = false;
			while (!success)
			{
				lock (this) { if (this.Abort) break; } //abort flag was set.... bail
				KernelInput input = null;
				lock (_kernelInput)
				{
					if (_kernelInput.Count > 0) input = _kernelInput.Dequeue();
				}
				if (input == null) //If we have run out of work sleep for a bit
				{
					Console.WriteLine("Lack of work for the GPU!! Taking a nap!!");
					Thread.Sleep(250);
					continue;
				}

				profiler.StartRegion("set buffers");
				bufLastWs.Data = input.LastWs;
				bufMidstates.Data = input.Midstates;
				bufExpIndexes.Data = input.ExpIndexes;
				bufResults.Data = input.Results;
				profiler.EndRegion("set buffers");

				profiler.StartRegion("write buffers");
				bufLastWs.EnqueueWrite();
				bufMidstates.EnqueueWrite();
				bufExpIndexes.EnqueueWrite();
				bufResults.EnqueueWrite();
				profiler.EndRegion("write buffers");

				profiler.StartRegion("run kernel");
				//kernel.EnqueueNDRangeKernel(1024*1024*16,128);
				kernel.EnqueueNDRangeKernel(workSize, workGroupSize);
				profiler.EndRegion("run kernel");

				profiler.StartRegion("read results");
				bufResults.EnqueueRead();
				profiler.EndRegion("read results");

				loop++;
				Console.Write("\r");
				long hashes = (long)workSize * (long)loop;
				Console.Write("LoopIteration:{0}  HashCount:{1:0.00}MH  Speed:{2:0.0}MH/s  Runtime:{3}  Predicted:{4}", 
				              loop, hashes / 1000000.0d, hashes/gpu_runtime_sw.ElapsedMilliseconds/1000.0d, 
				              gpu_runtime_sw.Elapsed.ToString().Split('.')[0], 
				              PredictedRuntime(prefix,suffix,hashes*1000/gpu_runtime_sw.ElapsedMilliseconds));

				profiler.StartRegion("check results");
				foreach (var result in input.Results)
				{
					if (result != 0)
					{
						try
						{
							Console.WriteLine();
							Console.WriteLine("Ding!! Delicions scallions for you!!");
							Console.WriteLine();
							Console.WriteLine("Exponent: {0}", result);
							input.Rsa.ChangePublicExponent((BigNumber)result);
							Console.WriteLine("Address/Hash: " + input.Rsa.OnionHash);
							Console.WriteLine();
							Console.WriteLine(input.Rsa.Rsa.PrivateKeyAsPEM);
							Console.WriteLine();
							success = true;
						}
						catch (OpenSslException /*ex*/) { }
					}
				}
				profiler.EndRegion("check results");
			}

			inputThread.Abort();//stop makin work
			profiler.EndRegion("total without init");
			Console.WriteLine(profiler.GetSummaryString());
			Console.WriteLine("{0:0.00} million hashes per second", ((long)loop * (long)workSize * (long)1000) / (double)profiler.GetTotalMS("total without init") / (double)1000000);
		}
	}
}

