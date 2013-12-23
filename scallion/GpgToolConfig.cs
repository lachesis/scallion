using System;

namespace scallion
{
	public class GpgToolConfig : IToolConfig
	{
		public GpgToolConfig(string pattern)
		{
		}

		public TimeSpan PredictRuntime(int hashRate);

		public bool CheckMatch(RSAWrapper rsa);

		public IList<BitmaskPatternsTuple> GenerateBitmaskPatterns();
	}
}

