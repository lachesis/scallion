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
	}
}
