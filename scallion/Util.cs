using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;

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
		public static void AppendLine(this StringBuilder builder, string format, params object[] args)
		{
			builder.AppendLine(string.Format(format, args));
		}
		public static void AppendLines(this StringBuilder builder, IEnumerable values)
		{
			foreach (var value in values)
			{
				builder.AppendLine(value.ToString());
			}
		}
		public static IEnumerable<int> Range(int max)
		{
			return Range(0, max);
		}
		public static IEnumerable<int> Range(int min, int max)
		{
			for (int i = min; i < max; i++)
			{
				yield return min;
			}
		}
		public static string ToDelimitedString(this IEnumerable items, string delimiter)
		{
			StringBuilder builder = new StringBuilder();
			foreach (var item in items)
			{
				builder.Append(item.ToString());
				builder.Append(delimiter);
			}
			if (builder.Length > 0) builder.Remove(builder.Length - delimiter.Length, delimiter.Length);
			return builder.ToString();
		}
		private const uint OFFSET_BASIS = 2166136261;
		private const uint FNV_PRIME = 16777619;
		public static uint FNVHash(uint a, uint b)
		{
			return (uint)((((OFFSET_BASIS ^ a) * FNV_PRIME) ^ b) * FNV_PRIME);
		}
		public static uint Rotate5(uint a)
		{
			return (a << 5) | (a >> 27);
		}
		public static uint FNVHash(uint a, uint b, uint c)
		{
			a = Rotate5(a);
			b = Rotate5(b);
			c = Rotate5(c);
			return (uint)((((((OFFSET_BASIS ^ a) * FNV_PRIME) ^ b) * FNV_PRIME) ^ c) * FNV_PRIME);
		}
	}
}
