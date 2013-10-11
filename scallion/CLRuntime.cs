using System;
using System.Linq;
using System.Collections.Generic;
using OpenSSL.Core;
using OpenSSL.Crypto;
using System.Threading;

namespace scallion
{
	public enum KernelType
	{
		Normal,
		Optimized4_9,
		Optimized4_11
	}

	public class CLRuntime
	{
		public static List<CLDeviceInfo> GetDevices()
		{
			return CLDeviceInfo.GetDeviceIds()
				.Select(i => new CLDeviceInfo(i))
				.Where(i => i.CompilerAvailable)
				.ToList();
		}

		private KernelType kernel_type;
		private int keySize;

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

		public class RandomList<T>
		{
			private System.Random _rnd = new System.Random(); 
			private List<T> _list = new List<T>();
			public void Push(T value)
			{
				_list.Add(value);
			}
			public T Pop()
			{
				if(_list.Count <= 0) return default(T);
				T ret = _list[_rnd.Next(0, _list.Count)];
				_list.Remove(ret);
				return ret;
			}
			public int Count
			{
				get { return _list.Count; }
			}
		}
		
		public class KernelInput
		{
			public KernelInput(KernelInput input, uint baseExp)
			{
				Rsa = input.Rsa;
				LastWs = input.LastWs;
				Midstates = input.Midstates;
				ExpIndexes = input.ExpIndexes;
				Results = input.Results;
				BaseExp = baseExp;
			}
			public KernelInput(int num_exps)
			{
				Rsa = new RSAWrapper();
				LastWs = new uint[num_exps * 16];
				Midstates = new uint[num_exps * 5];
				ExpIndexes = new int[num_exps];
				Results = new uint[128];
				BaseExp = EXP_MIN;
			}
			public readonly uint[] LastWs;
			public readonly uint[] Midstates;
			public readonly int[] ExpIndexes;
			public readonly RSAWrapper Rsa;
			public readonly uint[] Results;
			public readonly uint BaseExp;
		}
		const uint EXP_MIN = 0x01010001;
		const uint EXP_MAX = 0x7FFFFFFF;
		public bool Abort = false;
		private RandomList<KernelInput> _kernelInput = new RandomList<KernelInput>();
		private void CreateInput()
		{
			while (true)
			{
				bool inputQueueIsLow = false;
				lock (_kernelInput)	{ inputQueueIsLow = _kernelInput.Count < 300; }
				if (inputQueueIsLow)
				{
					int num_exps = (get_der_len(EXP_MAX) - get_der_len(EXP_MIN) + 1);
					KernelInput input = new KernelInput(num_exps);

					profiler.StartRegion("generate key");
					input.Rsa.GenerateKey(keySize); // Generate a key
					profiler.EndRegion("generate key");

					// Build DERs and calculate midstates for exponents of representitive lengths
					profiler.StartRegion("cpu precompute");
					int cur_exp_num = 0;
					BigNumber[] Exps = new BigNumber[num_exps];
					bool skip_flag = false;
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
						if (kernel_type == KernelType.Optimized4_9) {
							if(exp_index != 9) { // exponent index assumed to be 9 in the kernel
								Console.WriteLine("Exponent index doesn't match - skipping key");
								skip_flag = true;
								break;
							}
							if(i != 4) { // exponent length assumed to be 4 in the kernel
								Console.WriteLine("Exponent length doesn't match - skipping key");
								skip_flag = true;
								break;
							}
						}
						else if (kernel_type == KernelType.Optimized4_11) {
							if(exp_index != 11) { // exponent index assumed to be 9 in the kernel
								Console.WriteLine("Exponent index doesn't match - skipping key");
								skip_flag = true;
								break;
							}
							if(i != 4) { // exponent length assumed to be 4 in the kernel
								Console.WriteLine("Exponent length doesn't match - skipping key");
								skip_flag = true;
								break;
							}
						}

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

					if(skip_flag) continue; // we got a bad key - don't enqueue it

					List<KernelInput> inputs = new List<KernelInput>();
					inputs.Add(input);
					for (uint i = 1; i < (EXP_MAX - EXP_MIN) / 2 / workSize - 1; i++)
					{
						profiler.StartRegion("generate key");
						if(EXP_MIN + workSize * 2 * i >= EXP_MAX) throw new ArgumentException("base_exp > EXP_MAX");
						inputs.Add(new KernelInput(input, EXP_MIN + workSize * 2 * i));
						profiler.EndRegion("generate key");
					}
					lock (_kernelInput)//put input on queue
					{
						foreach (KernelInput i in inputs)
						{
							_kernelInput.Push(i);
						}
					}
					continue;//skip the sleep cause we might be really low
				}
				Thread.Sleep(50);
			}
		}

		private TimeSpan PredictedRuntime(double hashes_per_win, long speed)
		{
			//int len = prefix.Length;
			long runtime_sec = (long)(hashes_per_win / speed); //(long)Math.Pow(2,5*len-1) / speed;
			return TimeSpan.FromSeconds(runtime_sec);
		}

		private Profiler profiler = null;
		private uint workSize; 
		private List<Thread> inputThreads = new List<Thread>();

		const int MIN_CHARS = 7;
		const uint BIT_TABLE_LENGTH = 0x40000000; // in bits
		const uint BIT_TABLE_WORD_SIZE = 32;

		public void Run(ProgramParameters parms)
			 //int deviceId, int workGroupSize, int workSize, int numThreadsCreateWork, KernelType kernelt, int keysize, IEnumerable<string> patterns)
		{
			int deviceId = (int)parms.DeviceId;
			int workGroupSize = (int)parms.WorkGroupSize;
			int workSize = (int)parms.WorkSize;
			int numThreadsCreateWork = (int)parms.CpuThreads;
			KernelType kernelt = parms.KernelType;
			int keysize = (int)parms.KeySize;

			Console.WriteLine("Cooking up some delicions scallions...");
			this.workSize = (uint)workSize;
			profiler = new Profiler();
			#region init
			profiler.StartRegion("init");

			// Combine patterns into a single regexp and build one of Richard's objects
            var rp = new RegexPattern(parms.Regex);

			// Create bitmasks array for the GPU
			var gpu_bitmasks = rp.GenerateOnionPatternBitmasksForGpu(MIN_CHARS)
								 .Select(t => TorBase32.ToUIntArray(TorBase32.CreateBase32Mask(t)))
								 .SelectMany(t => t).ToArray();
			//Create Hash Table
			uint[] dataArray;
			ushort[] hashTable;
            uint[][] all_patterns;
			int max_items_per_key = 0;
			{
				Func<uint[], ushort> fnv =
					(pattern_arr) =>
					{
						uint f = Util.FNVHash(pattern_arr[0], pattern_arr[1], pattern_arr[2]);
						f = ((f >> 10) ^ f) & (uint)1023;
						return (ushort)f;
					};
				all_patterns = rp.GenerateOnionPatternsForGpu(7)
					.Select(i => TorBase32.ToUIntArray(TorBase32.FromBase32Str(i.Replace('.', 'a'))))
                    .ToArray();
                var gpu_dict_list = all_patterns
					.Select(i => new KeyValuePair<ushort, uint>(fnv(i), Util.FNVHash(i[0], i[1], i[2])))
					.GroupBy(i => i.Key)
					.OrderBy(i => i.Key)
					.ToList();

				dataArray = gpu_dict_list.SelectMany(i => i.Select(j => j.Value)).ToArray();
				hashTable = new ushort[1024]; //item 1 index, item 2 length
				int currIndex = 0;
				foreach (var item in gpu_dict_list)
				{
					int len = item.Count();
					hashTable[item.Key] = (ushort)currIndex;
					currIndex += len;
					if(len > max_items_per_key) max_items_per_key = len;
				}

				Console.WriteLine("Putting {0} patterns into {1} buckets.",currIndex,gpu_dict_list.Count);
			}

			// Set the key size
			keySize = keysize;

			// Find kernel name and check key size
			kernel_type = kernelt;
			string kernelFileName = null, kernelName = null;
			switch (kernel_type)
			{
				case KernelType.Normal:
					kernelFileName = "kernel.cl";
					kernelName = "normal";
					break;
				case KernelType.Optimized4_9:
					if (keySize != 1024) throw new ArgumentException("Kernel only works with keysize 1024.");
					kernelFileName = "kernel.cl";
					kernelName = "optimized";
					break;
				case KernelType.Optimized4_11:
					if (keySize != 2048 && keySize != 4096) throw new ArgumentException("Kernel only works with keysize 2048 or 4096.");
					kernelFileName = "kernel.cl";
					kernelName = "optimized";
					break;
				default:
					throw new ArgumentException("Pick a supported kernel.");
			}

			Console.WriteLine("Using kernel {0} from file {1} ({2})", kernelName, kernelFileName, kernel_type);

			//create device context and kernel
			CLDeviceInfo device = GetDevices()[deviceId];
			if ((uint)workGroupSize > device.MaxWorkGroupSize)
			{
				workGroupSize = (int)device.MaxWorkGroupSize;
			}
			Console.WriteLine("Using work group size {0}",workGroupSize);
			CLContext context = new CLContext(device.DeviceId);

			Console.Write("Compiling kernel... ");
			string kernel_text = KernelGenerator.GenerateKernel(parms,gpu_bitmasks.Length/3,max_items_per_key,gpu_bitmasks.Take(3).ToArray(),all_patterns[0],all_patterns.Length);
            if(parms.SaveGeneratedKernelPath != null)
                System.IO.File.WriteAllText(parms.SaveGeneratedKernelPath, kernel_text);
            IntPtr program = context.CreateAndCompileProgram(kernel_text);

			var hashes_per_win = 0.5 / rp.GenerateAllOnionPatternsForRegex().Select(t=>Math.Pow(2,-5*t.Count(q=>q!='.'))).Sum();
			Console.WriteLine("done.");

            //
            // Test SHA1 algo
            // 
            {
                Console.WriteLine("Testing SHA1 hash...");

                CLKernel shaTestKern = context.CreateKernel(program, "shaTest");
                CLBuffer<uint> bufSuccess = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadWrite | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, new uint[5]);
                shaTestKern.SetKernelArg(0, bufSuccess);

				shaTestKern.EnqueueNDRangeKernel(workSize, workGroupSize);

				bufSuccess.EnqueueRead(false);

                Console.WriteLine("Output: {0} {1} {2} {3} {4}", bufSuccess.Data[0], bufSuccess.Data[1], bufSuccess.Data[2], bufSuccess.Data[3], bufSuccess.Data[4]); 
            }

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
			CLBuffer<ushort> bufHashTable;
			CLBuffer<uint> bufDataArray;
			CLBuffer<uint> bufBitmasks;
			{
				bufHashTable = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, hashTable);
				bufDataArray = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, dataArray);
				bufBitmasks = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, gpu_bitmasks);
			}
			//Set kernel arguments
			lock (new object()) { } // Empty lock, resolves (or maybe hides) a race condition in SetKernelArg
			kernel.SetKernelArg(0, bufLastWs);
			kernel.SetKernelArg(1, bufMidstates);
			kernel.SetKernelArg(2, bufResults);
			kernel.SetKernelArg(3, (uint)EXP_MIN);
			kernel.SetKernelArg(4, (byte)get_der_len(EXP_MIN));
			kernel.SetKernelArg(5, bufExpIndexes);
			kernel.SetKernelArg(6, bufBitmasks);
			kernel.SetKernelArg(7, bufHashTable);
			kernel.SetKernelArg(8, bufDataArray);
			profiler.EndRegion("init");

			bufBitmasks.EnqueueWrite(true);
			bufHashTable.EnqueueWrite(true);
			bufDataArray.EnqueueWrite(true);

			//start the thread to generate input data
			for (int i = 0; i < numThreadsCreateWork; i++)
			{
				Thread inputThread = new Thread(CreateInput);
				inputThread.Start();
				inputThreads.Add(inputThread);
			}
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
					if (_kernelInput.Count > 0) input = _kernelInput.Pop();
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
				kernel.SetKernelArg(3, input.BaseExp);
				profiler.EndRegion("set buffers");

				profiler.StartRegion("write buffers");
				bufLastWs.EnqueueWrite(true);
				bufMidstates.EnqueueWrite(true);
				bufExpIndexes.EnqueueWrite(true);
				Array.Clear(bufResults.Data,0,bufResults.Data.Length);
				bufResults.EnqueueWrite(true);
				profiler.EndRegion("write buffers");

				kernel.EnqueueNDRangeKernel(workSize, workGroupSize);

				profiler.StartRegion("read results");
				bufResults.EnqueueRead(false);
				profiler.EndRegion("read results");

				loop++;
				Console.Write("\r");
				long hashes = (long)workSize * (long)loop;

				Console.Write("LoopIteration:{0}  HashCount:{1:0.00}MH  Speed:{2:0.0}MH/s  Runtime:{3}  Predicted:{4}  ", 
				              loop, hashes / 1000000.0d, hashes/gpu_runtime_sw.ElapsedMilliseconds/1000.0d, 
				              gpu_runtime_sw.Elapsed.ToString().Split('.')[0], 
				              PredictedRuntime(hashes_per_win,hashes*1000/gpu_runtime_sw.ElapsedMilliseconds));

				profiler.StartRegion("check results");
				foreach (var result in input.Results)
				{
					if (result != 0)
					{
						try
						{
							input.Rsa.ChangePublicExponent((BigNumber)result);

							string onion_hash = input.Rsa.OnionHash;
							Console.WriteLine("CPU checking hash: {0}",onion_hash);

							if (rp.DoesOnionHashMatchPattern(onion_hash))
							{
								Console.WriteLine();
								Console.WriteLine("Ding!! Delicious scallions for you!!");
								Console.WriteLine();

								string key = input.Rsa.Rsa.PrivateKeyAsPEM;

								if (parms.KeyOutputPath != null)
								{
									System.IO.File.AppendAllText(parms.KeyOutputPath,"Generated at: " + System.DateTime.Now.ToString("G") + "\n");
									System.IO.File.AppendAllText(parms.KeyOutputPath,"Address/Hash: " + onion_hash + ".onion\n");
									System.IO.File.AppendAllText(parms.KeyOutputPath,"RSA key: \n" + key + "\n\n");
								}

								Console.WriteLine("Exponent: {0}", result);
								input.Rsa.ChangePublicExponent((BigNumber)result);
								Console.WriteLine("Address/Hash: " + onion_hash + ".onion");
								Console.WriteLine();
								Console.WriteLine(key);
								Console.WriteLine();
                                if (!parms.ContinueGeneration) success = true;
							}
						}
						catch (OpenSslException /*ex*/) { }
					}
				}
				profiler.EndRegion("check results");
			}

			foreach (var thread in inputThreads) thread.Abort();
			profiler.EndRegion("total without init");
			Console.WriteLine(profiler.GetSummaryString());
			Console.WriteLine("{0:0.00} million hashes per second", ((long)loop * (long)workSize * (long)1000) / (double)profiler.GetTotalMS("total without init") / (double)1000000);
		}
	}
}

