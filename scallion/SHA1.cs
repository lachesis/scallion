using System;
using System.Linq;
using System.Collections.Generic;

namespace scallion
{
	public class SHA1
	{
		public SHA1()
		{
			Init();
		}

		public void Init()
		{
			H = new uint[] { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
		}

		public uint[] H {
			get; private set;
		}

		private byte[] pad_data(byte[] data)
		{
			int midlength = 64-data.Length%64-9;
			if(midlength < 0) midlength = 0;
			return (new byte[][] { data, new byte[] {0x80}, new byte[midlength], Mono.DataConverter.Pack("^L",new object[] { data.Length*8 }) }).SelectMany(i=>i).ToArray();
		}

		public List<uint[]> DataToPaddedBlocks(byte[] data)
		{
			data = pad_data(data);

			List<uint[]> ret = new List<uint[]>();
			for (int chunk = 0; chunk < data.Length/64; chunk++) {
				uint[] W = new uint[80];
				for (int k = 0; k < 16; k++) {
					int j = chunk*64 + k*4;
					W[k] = (uint)(data[j+0]<<24 | data[j+1]<<16 | data[j+2]<<8 | data[j+3]);
				}
				ret.Add(W);
			}
			return ret;
		}

		private uint rotateLeft(uint x, int n)
		{
		    return  (x << n) | (x >> (32-n));
		}

		// block size: 512b = 64B = 16W
		// W (80W long) is the 16W of work + scratch space (prepadded)
		public void SHA1_Block(uint[] W)
		{
	        uint A,B,C,D,E,K0,K1,K2,K3,temp;
	        int i;

	        K0 = 0x5A827999;
	        K1 = 0x6ED9EBA1;
	        K2 = 0x8F1BBCDC;
	        K3 = 0xCA62C1D6;

	        A = H[0];
	        B = H[1];
	        C = H[2];
	        D = H[3];
	        E = H[4];

	        for(i = 16; i < 80; i++)
	        {
	            W[i] = rotateLeft(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
	        }

	        for(i = 0; i < 20; i++)
	        {
	            temp = rotateLeft(A,5) + ((B & C) | ((~ B) & D)) + E + W[i] + K0;
	            E = D;
	            D = C;
	            C = rotateLeft(B, 30);
	            B = A;
	            A = temp;
	        }

	        for(i = 20; i < 40; i++)
	        {
	            temp = rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + K1;
	            E = D;
	            D = C;
	            C = rotateLeft(B, 30);
	            B = A;
	            A = temp;
	        }

	        for(i = 40; i < 60; i++)
	        {
	            temp = rotateLeft(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + K2;
	            E = D;
	            D = C;
	            C = rotateLeft(B, 30);
	            B = A;
	            A = temp;
	        }

	        for(i = 60; i < 80; i++)
	        {
	            temp = rotateLeft(A, 5) + (B ^ C ^ D)  + E + W[i] + K3;
	            E = D;
	            D = C;
	            C = rotateLeft(B, 30);
	            B = A;
	            A = temp;
	        }

	        H[0] = (H[0] + A);
	        H[1] = (H[1] + B);
	        H[2] = (H[2] + C);
	        H[3] = (H[3] + D);
	        H[4] = (H[4] + E);
		}
	}
}

