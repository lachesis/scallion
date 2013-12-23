using System;
using System.Collections.Generic;

namespace scallion
{
	public class OnionToolConfig : ToolConfig
	{

		public OnionToolConfig(string pattern) : base(pattern)
		{
            
		}

        public override TimeSpan PredictRuntime(int hashRate)
        {
			// 5 = log_2(32) [for base 32 onion address]
			var hashes_per_win = _regex.GenerateAllOnionPatternsForRegex().Select(t=>Math.Pow(2,5*t.Count(q=>q!='.') - 1)).Sum();
			long runtime_sec = (long)(hashes_per_win / hashRate);
			return TimeSpan.FromSeconds(runtime_sec);
        }

        public override bool CheckMatch(RSAWrapper rsa)
        {
			return _regex.DoesOnionHashMatchPattern(rsa.OnionHash);
        }

        public override IList<BitmaskPatternsTuple> GenerateBitmaskPatterns()
        {
            throw new NotImplementedException();
        }
	}
}

