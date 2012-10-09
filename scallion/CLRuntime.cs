using System;
using System.Linq;
using System.Collections.Generic;
using OpenSSL.Core;
using OpenSSL.Crypto;

namespace scallion
{
	public static class CLRuntime
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

		public static void Run(int deviceId)
		{
			Profiler profiler = new Profiler();

			profiler.StartRegion("init");
			CLDeviceInfo device = GetDevices()[deviceId];
			CLContext context = new CLContext(device.DeviceId);
			IntPtr program = context.CreateAndCompileProgram(
				System.IO.File.ReadAllText(
					System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + System.IO.Path.DirectorySeparatorChar + "kernel.cl"
				)
			);
			CLKernel kernel = context.CreateKernel(program, "shasearch");
			
			const ulong EXP_MIN = 0x01010001;
			const ulong EXP_MAX = 0x7FFFFFFF;

			int num_exps = (get_der_len(EXP_MAX) - get_der_len(EXP_MIN) + 1);
			int cur_exp_num = 0; 
			uint[] LastWs = new uint[num_exps*16];
			uint[] Midstates = new uint[num_exps*5];
			int[] ExpIndexes = new int[num_exps];

			BigNumber[] Exps = new BigNumber[num_exps];

			uint[] Results = new uint[128];

			CLBuffer<uint> bufLastWs = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, LastWs);
			CLBuffer<uint> bufMidstates = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Midstates);
			CLBuffer<int> bufExpIndexes = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, ExpIndexes);
			CLBuffer<uint> bufResults = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadWrite | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Results);

			//__kernel void kernel(__const uint32* LastWs, __const uint32* Midstates, __const int32* ExpIndexes, __global uint32* Results, uint64 base_exp, uint8 len_start){
			uint[] Pattern = TorBase32.ToUIntArray(TorBase32.FromBase32Str("tronro".PadRight(16,'a')));
			uint[] Bitmask = TorBase32.ToUIntArray(TorBase32.CreateBase32Mask("xxxxxx".PadRight(16,'_')));
			CLBuffer<uint> bufPattern = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Pattern);
			CLBuffer<uint> bufBitmask = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Bitmask);

			lock(new object()) { } // Empty lock, resolves (or maybe hides) a race condition in SetKernelArg

			kernel.SetKernelArg(0, bufLastWs);			
			kernel.SetKernelArg(1, bufMidstates);
			kernel.SetKernelArg(2, bufExpIndexes);
			kernel.SetKernelArg(3, bufResults);
			kernel.SetKernelArg(4, EXP_MIN);
			kernel.SetKernelArg(5, (byte)get_der_len(EXP_MIN));
			kernel.SetKernelArg(6, bufPattern);
			kernel.SetKernelArg(7, bufBitmask);
			profiler.EndRegion("init");
		
			int loop = 0;

			profiler.StartRegion("total without init");
			bool success = false;
			while(!success)
			{
				profiler.StartRegion("generate key");
				RSAWrapper rsa = new RSAWrapper();
				rsa.GenerateKey(1024); // Generate a key
				profiler.EndRegion("generate key");

				profiler.StartRegion("clear results array");
				Array.Clear(Results,0,Results.Length);
				profiler.EndRegion("clear results array");

				// Build DERs and calculate midstates for exponents of representitive lengths
				profiler.StartRegion("cpu precompute");
				cur_exp_num = 0;
				for (int i = get_der_len(EXP_MIN); i <= get_der_len(EXP_MAX); i++) {
					ulong exp = (ulong)0x01 << (int)((i-1)*8);

					// Set the exponent in the RSA key
					// NO SANITY CHECK - just for building a DER
					rsa.Rsa.PublicExponent = (BigNumber)exp;
					Exps[cur_exp_num] = (BigNumber)exp;

					// Get the DER
					byte[] der = rsa.DER;
					int exp_index = der.Length % 64 - i;

					// Put the DER into Ws
					SHA1 Sha1 = new SHA1();
					List<uint[]> Ws = Sha1.DataToPaddedBlocks(der);

					// Put all but the last block through the hash
					Ws.Take(Ws.Count-1).Select((t) => {
						Sha1.SHA1_Block(t);
						return t;
					}).ToArray();

					// Put the midstate, the last W block, and the byte index of the exponent into the CL buffers
					Sha1.H.CopyTo(Midstates,5*cur_exp_num);
					Ws.Last().Take(16).ToArray().CopyTo(LastWs,16*cur_exp_num);
					ExpIndexes[cur_exp_num] = exp_index; 

					// Increment the current exponent size
					cur_exp_num++;

					break;
				}
				profiler.EndRegion("cpu precompute");

				profiler.StartRegion("write buffers");
				bufLastWs.EnqueueWrite();
				bufMidstates.EnqueueWrite();
				bufExpIndexes.EnqueueWrite();
				bufResults.EnqueueWrite();
				profiler.EndRegion("write buffers");

				profiler.StartRegion("run kernel");
				kernel.EnqueueNDRangeKernel(1024*1024*16,128);
				profiler.EndRegion("run kernel");

				profiler.StartRegion("read results");
				bufResults.EnqueueRead();
				profiler.EndRegion("read results");

				loop++;
				Console.WriteLine("Loop iteration {0}; Hash Count {1}",loop,1024*1024*16*loop);

				profiler.StartRegion("check results");
				foreach (var result in Results)
				{
					if(result != 0)
					{
						try {
							Console.WriteLine("Exp: {0}",result);
							rsa.ChangePublicExponent((BigNumber)result);
							Console.WriteLine(rsa.OnionHash);
							Console.WriteLine(rsa.Rsa.PrivateKeyAsPEM);
							success = true;	
						} catch (Exception ex) {
						
						}
					}
				}
				profiler.EndRegion("check results");
			}

			profiler.EndRegion("total without init");
			Console.WriteLine(profiler.GetSummaryString());
			Console.WriteLine("Hashes / second: {0}",((long)loop*1024*1024*16*1000)/profiler.GetTotalMS("total without init"));
		}
	}
}

