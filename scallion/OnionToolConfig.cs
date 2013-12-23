using System;

namespace scallion
{
	public class OnionToolConfig : IToolConfig
	{
		public OnionToolConfig(string pattern)
		{
		}

		public TimeSpan PredictRuntime(int hashRate);

		public bool CheckMatch(RSAWrapper rsa);

		public IList<BitmaskPatternsTuple> GenerateBitmaskPatterns();
	}
}

