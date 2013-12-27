using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using OpenSSL.Core;
using OpenSSL.Crypto;
using System.Threading;

namespace scallion
{
	public enum KernelType
	{
		Normal,
		Optimized4
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

		public static void OutputKey(RSAWrapper rsa)
		{
			ProgramParameters parms = ProgramParameters.Instance;

			Console.WriteLine();
			Console.WriteLine("Ding!! Delicious scallions for you!!");
			Console.WriteLine();

			if (parms.KeyOutputPath != null)
			{
				System.IO.File.AppendAllText(parms.KeyOutputPath,"Generated at: " + System.DateTime.Now.ToString("G") + "\n");
				System.IO.File.AppendAllText(parms.KeyOutputPath,"Address/Hash: " + rsa.OnionHash + ".onion\n");
				System.IO.File.AppendAllText(parms.KeyOutputPath,"Public Modulus: " + rsa.Rsa.PublicModulus.ToDecimalString() + "\n");
				System.IO.File.AppendAllText(parms.KeyOutputPath,"Public Exponent: " + rsa.Rsa.PublicExponent.ToDecimalString() + "\n");
				if (rsa.HasPrivateKey) {
					System.IO.File.AppendAllText(parms.KeyOutputPath,"RSA key: \n" + rsa.Rsa.PrivateKeyAsPEM + "\n");
				}
				System.IO.File.AppendAllText(parms.KeyOutputPath, "\n\n");
			}

			Console.WriteLine("Public Modulus:  {0}", rsa.Rsa.PublicModulus.ToDecimalString());
			Console.WriteLine("Public Exponent: {0}", rsa.Rsa.PublicExponent.ToDecimalString());
			Console.WriteLine("Address/Hash: " + rsa.OnionHash + ".onion");

			Console.WriteLine();
			if (rsa.HasPrivateKey) {
				Console.WriteLine(rsa.Rsa.PrivateKeyAsPEM);
				Console.WriteLine();
			}
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
				BaseExp = ProgramParameters.Instance.ToolConfig.MinimumExponent;
			}
			public readonly uint[] LastWs;
			public readonly uint[] Midstates;
			public readonly int[] ExpIndexes;
			public readonly RSAWrapper Rsa;
			public readonly uint[] Results;
			public readonly uint BaseExp;
		}

		public bool Abort = false;
		private RandomList<KernelInput> _kernelInput = new RandomList<KernelInput>();
		private void CreateInput()
		{
			ProgramParameters parms = ProgramParameters.Instance;

			while (true)
			{
				bool inputQueueIsLow = false;
				lock (_kernelInput)	{ inputQueueIsLow = _kernelInput.Count < 300; }
				if (inputQueueIsLow)
				{
					KernelInput input = new KernelInput(1);

					// Read moduli from file or generate them if possible
					if (parms.RSAPublicModuli != null)
					{
						if (parms.RSAPublicModuli.Count > 0) {
							input.Rsa.Rsa.PublicModulus = parms.RSAPublicModuli.Dequeue();
						} else {
							break;
						}
					}
					else
					{
						profiler.StartRegion("generate key");
						input.Rsa.GenerateKey((int)parms.KeySize); // Generate a key
						profiler.EndRegion("generate key");
					}

					// Build DERs and calculate midstates for exponents of representitive lengths
					profiler.StartRegion("cpu precompute");
					bool skip_flag = false;

					uint exp = parms.ToolConfig.MinimumExponent;

					// Set the exponent in the RSA key
					// NO SANITY CHECK - just for building a DER
					input.Rsa.Rsa.PublicExponent = (BigNumber)exp;

					// Get the GPG v4 packet
					int exp_index;
					byte[] data = parms.ToolConfig.GetPublicKeyData(input.Rsa, out exp_index);
					//byte[] data = input.Rsa.GPG_v4Packet(out exp_index);
					exp_index %= 64; // SHA-1 block size
				
					if(exp_index != parms.ExponentIndex) {
						Console.WriteLine("Exponent index doesn't match - skipping key");
						skip_flag = true;
						break;
					}
					/*if(i != 4) { // exponent length assumed to be 4 in the kernel
						Console.WriteLine("Exponent length doesn't match - skipping key");
						skip_flag = true;
						break;
					}*/

					// Put the v4 packet into Ws
					SHA1 Sha1 = new SHA1();
					List<uint[]> Ws = Sha1.DataToPaddedBlocks(data);

					// Put all but the last block through the hash
					Ws.Take(Ws.Count - 1).Select((t) => {
						Sha1.SHA1_Block(t);
						return t;
					}).ToArray();

					// Put the midstate, the last W block, and the byte index of the exponent into the CL buffers
					Sha1.H.CopyTo(input.Midstates, 0);
					Ws.Last().Take(16).ToArray().CopyTo(input.LastWs, 0);
					input.ExpIndexes[0] = exp_index;

					profiler.EndRegion("cpu precompute");

					if(skip_flag) continue; // we got a bad key - don't enqueue it

					List<KernelInput> inputs = new List<KernelInput>();
					inputs.Add(input);

					// Stretch the key for multiple exponents (if more than one kernel iteration (work group?) will be needed)
					for (uint i = 1; i < (parms.ToolConfig.MaximumExponent - parms.ToolConfig.MinimumExponent) / 2 / workSize - 1; i++)
					{
						//profiler.StartRegion("generate key");
						if(parms.ToolConfig.MinimumExponent + workSize * 2 * i >= parms.ToolConfig.MaximumExponent)
							throw new ArgumentException("base_exp > EXP_MAX");
						inputs.Add(new KernelInput(input, parms.ToolConfig.MinimumExponent + workSize * 2 * i));
						//profiler.EndRegion("generate key");
					}

					// TODO: Stretch the key for multiple time stamps for GPG

					lock (_kernelInput)//put input on queue
					{
						foreach (KernelInput i in inputs)
						{
							_kernelInput.Push(i);
						}
						//Console.WriteLine("[DEBUG] Input pool size: {0}", _kernelInput.Count);
					}
					continue;//skip the sleep cause we might be really low
				}
				Thread.Sleep(50);
			}
		}
		/*private void CreateInputTOR()
		{
			ProgramParameters parms = ProgramParameters.Instance;

			while (true)
			{
				bool inputQueueIsLow = false;
				lock (_kernelInput)	{ inputQueueIsLow = _kernelInput.Count < 300; }
				if (inputQueueIsLow)
				{
					int num_exps = (get_der_len(EXP_MAX) - get_der_len(EXP_MIN) + 1);
					KernelInput input = new KernelInput(num_exps);

					// Read moduli from file or generate them if possible
					if (parms.RSAPublicModuli != null)
					{
						if (parms.RSAPublicModuli.Count > 0) {
							input.Rsa.Rsa.PublicModulus = parms.RSAPublicModuli.Dequeue();
						} else {
							break;
						}
					}
					else
					{
						profiler.StartRegion("generate key");
						input.Rsa.GenerateKey(keySize); // Generate a key
						profiler.EndRegion("generate key");
					}

					// Build DERs and calculate midstates for exponents of representitive lengths
					profiler.StartRegion("cpu precompute");
					int cur_exp_num = 0;
					BigNumber[] Exps = new BigNumber[num_exps];
					bool skip_flag = false;

					// With EXP_MIN = 0x01010001 and EXP_MAX = 0x7FFFFFFF, only one iteration (i = 4)
					for (int i = get_der_len(EXP_MIN); i <= get_der_len(EXP_MAX); i++)
					{
						// With i = 4, exp = 0x01000000 (just a placeholder in the DER)
						ulong exp = (ulong)0x01 << (int)((i - 1) * 8);

						// Set the exponent in the RSA key
						// NO SANITY CHECK - just for building a DER
						input.Rsa.Rsa.PublicExponent = (BigNumber)exp;
						Exps[cur_exp_num] = (BigNumber)exp;

						// Get the DER
						byte[] der = input.Rsa.DER;
						int exp_index = der.Length % 64 - i;
						if(exp_index != parms.ExponentIndex) {
							Console.WriteLine("Exponent index doesn't match - skipping key");
							skip_flag = true;
							break;
						}
						if(i != 4) { // exponent length assumed to be 4 in the kernel
							Console.WriteLine("Exponent length doesn't match - skipping key");
							skip_flag = true;
							break;
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
						//profiler.StartRegion("generate key");
						if(EXP_MIN + workSize * 2 * i >= EXP_MAX) throw new ArgumentException("base_exp > EXP_MAX");
						inputs.Add(new KernelInput(input, EXP_MIN + workSize * 2 * i));
						//profiler.EndRegion("generate key");
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
		}*/

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
		//const uint BIT_TABLE_LENGTH = 0x40000000; // in bits
		//const uint BIT_TABLE_WORD_SIZE = 32;

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

			// Create a tool config
			if (parms.GPGMode) {
				//parms.ToolConfig = new GpgToolConfig(parms.Regex);
			} else {
				parms.ToolConfig = new OnionToolConfig(parms.Regex);
			}

			// Find kernel name and check key size
			kernel_type = kernelt;
			string kernelFileName = null, kernelName = null;
			switch (kernel_type)
			{
				case KernelType.Normal:
					kernelFileName = "kernel.cl";
					kernelName = "normal";
					break;
				case KernelType.Optimized4:
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
			string kernel_text = KernelGenerator.GenerateKernel(parms, parms.ToolConfig, parms.ExponentIndex);
			//string kernel_text = KernelGenerator.GenerateKernel(parms,gpu_bitmasks.Length/3,max_items_per_key,gpu_bitmasks.Take(3).ToArray(),all_patterns[0],all_patterns.Length,parms.ExponentIndex);
            if(parms.SaveGeneratedKernelPath != null)
                System.IO.File.WriteAllText(parms.SaveGeneratedKernelPath, kernel_text);
            IntPtr program = context.CreateAndCompileProgram(kernel_text);

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

                // Calculate the SHA1 CPU-side
                System.Security.Cryptography.SHA1 sha = new System.Security.Cryptography.SHA1CryptoServiceProvider(); 

                String testdata = "Hello world!";
                byte[] cpuhash = sha.ComputeHash(Encoding.ASCII.GetBytes(testdata));
                StringBuilder cpuhex = new StringBuilder(cpuhash.Length * 2);
                foreach (byte b in cpuhash)
                    cpuhex.AppendFormat("{0:x2}", b);
                Console.WriteLine("CPU SHA-1: {0}", cpuhex.ToString());

                // Convert the SHA1 GPU-side to hex
                String gpuhex = String.Format("{0:x8}{1:x8}{2:x8}{3:x8}{4:x8}", bufSuccess.Data[0], bufSuccess.Data[1], bufSuccess.Data[2], bufSuccess.Data[3], bufSuccess.Data[4]);  

                Console.WriteLine("GPU SHA-1: {0}", gpuhex);
                
                if (gpuhex != cpuhex.ToString()) {
                    Console.WriteLine();
                    Console.WriteLine("******************************* ERROR ERROR ERROR *******************************");
                    Console.WriteLine("*                                                                               *");
                    Console.WriteLine("* GPU and CPU SHA-1 calculations do NOT match.                                  *");
                    Console.WriteLine("* Hashing will NOT work until this is resolved.                                 *");
                    Console.WriteLine("* The program will continue, but WILL NOT find a valid match.                   *");
                    Console.WriteLine("*                                                                               *");
                    Console.WriteLine("* See https://github.com/lachesis/scallion/issues/11#issuecomment-29046835      *");
                    Console.WriteLine("*                                                                               *");
                    Console.WriteLine("*********************************************************************************");
                    Console.WriteLine();
                }
                else
                {
                    Console.WriteLine("Looks good!");
                }
            }

			CLKernel kernel = context.CreateKernel(program, kernelName);
			//Create buffers
			CLBuffer<uint> bufLastWs;
			CLBuffer<uint> bufMidstates;
			CLBuffer<int> bufExpIndexes;
			CLBuffer<uint> bufResults;
			{
				int num_exps = 1;
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
				bufHashTable = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, parms.ToolConfig.HashTable);
				bufDataArray = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, parms.ToolConfig.PackedPatterns);
				bufBitmasks = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, parms.ToolConfig.PackedBitmaks);
			}
			//Set kernel arguments
			lock (new object()) { } // Empty lock, resolves (or maybe hides) a race condition in SetKernelArg
			kernel.SetKernelArg(0, bufLastWs);
			kernel.SetKernelArg(1, bufMidstates);
			kernel.SetKernelArg(2, bufResults);
			kernel.SetKernelArg(3, (uint)parms.ToolConfig.MinimumExponent);
			kernel.SetKernelArg(4, (byte)parms.ExponentIndex); // TODO: This is in like 4 places...
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
					Thread.Sleep(2500);
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
				              parms.ToolConfig.PredictRuntime(hashes * 1000/gpu_runtime_sw.ElapsedMilliseconds));

				profiler.StartRegion("check results");
				/*input.Rsa.Rsa.PublicExponent = (BigNumber)input.Results[5];
				uint[] hash = new uint[5];
				Array.Copy(input.Results, hash, 5);
				String gpuhashhex = String.Format("{0:x8}{1:x8}{2:x8}{3:x8}{4:x8}", input.Results[0], input.Results[1], input.Results[2], input.Results[3], input.Results[4]);
				Console.WriteLine("gpu hash: {0}", gpuhashhex);
				Console.WriteLine("cpu hash: {0}", input.Rsa.GPG_fingerprint_string);
				success = true;
				break;*/

				foreach (var result in input.Results)
				{
					if (result != 0)
					{
						try
						{
							input.Rsa.ChangePublicExponent((BigNumber)result);
							//input.Rsa.Rsa.PublicExponent = (BigNumber)result;

							// TODO :Real code
							//Console.WriteLine("Found key with fingerprint: {0}", input.Rsa.GPG_fingerprint_string);
							//System.IO.File.WriteAllText(String.Format("/tmp/{0}.sec.asc", input.Rsa.GPG_fingerprint_string), input.Rsa.GPG_privkey_export);

							/*if (input.Rsa.HasPrivateKey) {
								Console.WriteLine(input.Rsa.Rsa.PrivateKeyAsPEM);
								Console.WriteLine();
							}*/

                            if (!parms.ContinueGeneration) success = true;

							//////
							string onion_hash = input.Rsa.OnionHash;
							Console.WriteLine("CPU checking hash: {0}",onion_hash);

							if (parms.ToolConfig.CheckMatch(input.Rsa))
							{
								input.Rsa.ChangePublicExponent(result);
								OutputKey(input.Rsa);

                                if (!parms.ContinueGeneration) success = true;
							}
						}
						catch (OpenSslException /*ex*/) { }
					}
				}
				profiler.EndRegion("check results");

				// Mark key as used (if configured)
				if (parms.UsedModuliFile != null) {
					parms.UsedModuliFile.WriteLine(input.Rsa.Rsa.PublicModulus.ToDecimalString());
				}
			}

			foreach (var thread in inputThreads) thread.Abort();
			profiler.EndRegion("total without init");
			Console.WriteLine(profiler.GetSummaryString());
			Console.WriteLine("{0:0.00} million hashes per second", ((long)loop * (long)workSize * (long)1000) / (double)profiler.GetTotalMS("total without init") / (double)1000000);
		}
	}
}

