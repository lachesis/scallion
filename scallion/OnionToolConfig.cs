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
            throw new NotImplementedException();
        }

        public override bool CheckMatch(RSAWrapper rsa)
        {
            throw new NotImplementedException();
        }

        public override IList<BitmaskPatternsTuple> GenerateBitmaskPatterns()
        {
            throw new NotImplementedException();
        }
	}
}

