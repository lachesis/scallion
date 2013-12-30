using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace scallion
{
	public static class TorBase32
	{
		public static uint[] ToUIntArray(this Byte[] byteArray)
		{
			byte[] padded = new byte[(int)Math.Ceiling(byteArray.Length / 4f) * 4];
			byteArray.CopyTo(padded, 0);

			uint[] ret = new uint[(int)Math.Ceiling(padded.Length / 4f)];
			for (int i = 0; i < padded.Length; i += 4)
				ret[i / 4] = (uint)(padded[i] << 24) | (uint)(padded[i + 1] << 16) | (uint)(padded[i + 2] << 8) | (uint)(padded[i + 3] << 0);
			return ret;
		}

		public static byte[] CreateBase32Mask(string mask)
		{
			// 7 = all 1 (bits), a = all 0 (bits)
			return FromBase32Str(Regex.Replace(mask.ToLower(), "[^.]", "7").Replace(".", "a"));
		}

		public static byte[] FromBase32Str(string str)
		{
			byte[] src = Encoding.ASCII.GetBytes(str);
			int srclen = src.Length;
			int nbits = src.Length * 5;
			if (nbits % 8 != 0) throw new System.ArgumentException("We need an even multiple of 8 bits.");
			Byte[] tmp = new byte[srclen];
			for (int j = 0; j < srclen; ++j)
			{
				if (src[j] > 0x60 && src[j] < 0x7B) tmp[j] = (byte)(src[j] - (byte)0x61);
				else if (src[j] > 0x31 && src[j] < 0x38) tmp[j] = (byte)(src[j] - (byte)0x18);
				else if (src[j] > 0x40 && src[j] < 0x5B) tmp[j] = (byte)(src[j] - (byte)0x41);
				else
				{
					throw new System.ArgumentException("Illegal character in base32 encoded string");
				}
			}

			/* Assemble result byte-wise by applying five possible cases. */
			byte[] dest = new byte[srclen * 5 / 8];
			for (int i = 0, bit = 0; bit < nbits; ++i, bit += 8)
			{
				switch (bit % 40)
				{
					case 0:
						dest[i] = (byte)((((byte)tmp[(bit / 5)]) << 3) +
								  (((byte)tmp[(bit / 5) + 1]) >> 2));
						break;
					case 8:
						dest[i] = (byte)((((byte)tmp[(bit / 5)]) << 6) +
								  (((byte)tmp[(bit / 5) + 1]) << 1) +
								  (((byte)tmp[(bit / 5) + 2]) >> 4));
						break;
					case 16:
						dest[i] = (byte)((((byte)tmp[(bit / 5)]) << 4) +
								  (((byte)tmp[(bit / 5) + 1]) >> 1));
						break;
					case 24:
						dest[i] = (byte)((((byte)tmp[(bit / 5)]) << 7) +
								  (((byte)tmp[(bit / 5) + 1]) << 2) +
								  (((byte)tmp[(bit / 5) + 2]) >> 3));
						break;
					case 32:
						dest[i] = (byte)((((byte)tmp[(bit / 5)]) << 5) +
								  ((byte)tmp[(bit / 5) + 1]));
						break;
				}
			}
			return dest;
		}

		public static string ToBase32Str(byte[] src)
		{
			const string BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567";
			int i, v, u, bit;
			int nbits = src.Length * 8;

			StringBuilder sb = new StringBuilder();
			if (nbits % 5 != 0) throw new System.ArgumentException("We need an even multiple of 5 bits.");

			for (i = 0, bit = 0; bit < nbits; ++i, bit += 5)
			{
				/* set v to the 16-bit value starting at src[bits/8], 0-padded. */
				v = ((byte)src[bit / 8]) << 8;
				if (bit + 5 < nbits)
					v += (byte)src[(bit / 8) + 1];
				/* set u to the 5-bit value at the bit'th bit of src. */
				u = (v >> (11 - (bit % 8))) & 0x1F;
				sb.Append(BASE32_CHARS[u]);
			}
			return sb.ToString();
		}
	}
}
