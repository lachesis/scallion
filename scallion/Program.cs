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
		public static List<CLDeviceInfo> GetDevices()
		{
			return CLDeviceInfo.GetDeviceIds()
				.Select(i => new CLDeviceInfo(i))
				.Where(i => i.CompilerAvailable)
				.ToList();
		}
		public static void ListDevices()
		{
			int deviceId = 0;
			foreach (CLDeviceInfo device in GetDevices())
			{
				if (!device.CompilerAvailable) continue;
				Console.WriteLine("Id:{0} Name:{1}", deviceId, device.Name.Trim());
				deviceId++;
			}
		}
		public static void Help()
		{
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
		static void Main(string[] args)
		{
			Mode mode = Mode.Normal;
			int deviceId = 0;
			Func<Mode, Action<string>> parseMode = (m) => (s) => { if (!string.IsNullOrEmpty(s)) { mode = m; } };
			OptionSet p = new OptionSet()
				.Add("h|?|help", parseMode(Mode.Help))
				.Add("ld|ldevice", parseMode(Mode.ListDevices))
				.Add("d|device", (i) => { if (!string.IsNullOrEmpty(i)) { deviceId = int.Parse(i); } });
			List<string> extra = p.Parse(args);

			switch (mode)
			{
				case Mode.Help:
					Help();
					break;
				case Mode.ListDevices:
					ListDevices();
					break;
			}

			//string x = RSAWrapper.tobase32str(new byte[] { 0x9c, 0x5c, 0xde, 0x73, 0x9c, 0xe7, 0x39, 0xce, 0x73, 0x9c },10);
			//Console.WriteLine(x);

			CLDeviceInfo device = GetDevices()[deviceId];
			CLContext context = new CLContext(device.DeviceId);
			IntPtr program = context.CreateAndCompileProgram(
				System.IO.File.ReadAllText(
					System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + System.IO.Path.DirectorySeparatorChar + "kernel.cl"
				)
			);
			CLKernel kernel = context.CreateKernel(program, "shasearch");
			
			const ulong EXP_MIN = 0x10001;
			const ulong EXP_MAX = 0xFFFFFFFFFF;

			int num_exps = (get_der_len(EXP_MAX) - get_der_len(EXP_MIN) + 1);
			int cur_exp_num = 0; 
			uint[] LastWs = new uint[num_exps*16];
			uint[] Midstates = new uint[num_exps*5];
			int[] ExpIndexes = new int[num_exps];

			BigNumber[] Exps = new BigNumber[num_exps];

			ulong[] Results = new ulong[1024*1024];
			CLBuffer<uint> bufLastWs = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, LastWs);
			CLBuffer<uint> bufMidstates = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Midstates);
			CLBuffer<int> bufExpIndexes = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, ExpIndexes);
			CLBuffer<ulong> bufResults = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadWrite | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Results);

			//__kernel void kernel(__const uint32* LastWs, __const uint32* Midstates, __const int32* ExpIndexes, __global uint32* Results, uint64 base_exp, uint8 len_start){

			uint[] Pattern = new uint[] { 0x5f8dae2a, 0x00000000, 0x00000000 };
			uint[] Bitmask = new uint[] { 0xffffff00, 0x00000000, 0x00000000 };
			CLBuffer<uint> bufPattern = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Pattern);
			CLBuffer<uint> bufBitmask = context.CreateBuffer(OpenTK.Compute.CL10.MemFlags.MemReadOnly | OpenTK.Compute.CL10.MemFlags.MemCopyHostPtr, Bitmask);

			kernel.SetKernelArg(0, bufLastWs);
			kernel.SetKernelArg(1, bufMidstates);
			kernel.SetKernelArg(2, bufExpIndexes);
			kernel.SetKernelArg(3, bufResults);
			kernel.SetKernelArg(4, EXP_MIN);
			kernel.SetKernelArg(5, (byte)get_der_len(EXP_MIN));
			kernel.SetKernelArg(6, bufPattern);
			kernel.SetKernelArg(7, bufBitmask);

			bool success = false;
			while(!success)
			{
				RSAWrapper rsa = new RSAWrapper("key.pem");
				//rsa.GenerateKey(1024); // Generate a key

				Array.Clear(Results,0,Results.Length);

				// Build DERs and calculate midstates for exponents of representitive lengths
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

				bufLastWs.EnqueueWrite();
				bufMidstates.EnqueueWrite();
				bufExpIndexes.EnqueueWrite();
				bufResults.EnqueueWrite();

				kernel.EnqueueNDRangeKernel(1,1); //1024*1024,128);
	//			ulong j = kernel.KernelPreferredWorkGroupSizeMultiple;

				bufResults.EnqueueRead();

				rsa.ChangePublicExponent((BigNumber)Results[0]);

				SHA1 my = new SHA1();
				my.DataToPaddedBlocks(rsa.DER).Select(tttttt=>{my.SHA1_Block(tttttt); return 0;}).ToArray();
				var q = my.H;

				var s = new System.Security.Cryptography.SHA1Managed();
				byte[] b = s.ComputeHash(rsa.DER);
				string s2222 = BitConverter.ToString(b);

				//"CAD8DAB1-AF44AC15-E3-F9-54-DE-DF-98-FD-32-76-20-E9-AD"

				Console.WriteLine(LastWs);

				Console.WriteLine(Results);

				foreach (var result in Results)
				{
					if(result != 0)
					{
						rsa.ChangePublicExponent((BigNumber)result);
						Console.WriteLine(rsa.OnionHash);
						//Console.WriteLine(
						//Console.WriteLine(rsa.DER
						Console.WriteLine(rsa.Rsa.PrivateKeyAsPEM);
						success = true;
					}
				}
			}
		}
	}
}
