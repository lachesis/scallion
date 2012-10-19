using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace scallion
{
	public static class Util
	{
		public static IEnumerable<KeyValuePair<int, T>> Enumerate<T>(this IEnumerable<T> items)
		{
			int index = 0;
			foreach (T item in items)
			{
				yield return new KeyValuePair<int, T>(index, item);
				index++;
			}
		}

		private const uint OFFSET_BASIS = 2166136261;
		private const uint FNV_PRIME = 16777619;
		public static uint FNVHash(uint a, uint b)
		{
			return (uint)((((OFFSET_BASIS ^ a) * FNV_PRIME) ^ b) * FNV_PRIME);
		}
		public static uint FNVHash(uint a, uint b, uint c)
		{
			return (uint)((((((OFFSET_BASIS ^ a) * FNV_PRIME) ^ b) * FNV_PRIME) ^ c) * FNV_PRIME);
		}
	}
}
