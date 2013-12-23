using System;
using System.Collections.Generic;

namespace scallion
{
	public class BitmaskPatternsTuple
	{
		public uint[] Bitmask;
		public IList<uint[]> Patterns;
	} 

	public interface IToolConfig
	{
		TimeSpan PredictRuntime(int hashRate);

		bool CheckMatch(RSAWrapper rsa);

		IList<BitmaskPatternsTuple> GenerateBitmaskPatterns();
	}
}

