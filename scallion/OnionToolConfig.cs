using System;
using System.Collections.Generic;
using System.Linq;

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
            // Create bitmasks array for the GPU
            var gpu_bitmasks = _regex.GenerateOnionPatternBitmasksForGpu(7) //MIN_CHARS
                     .Select(t => TorBase32.ToUIntArray(TorBase32.CreateBase32Mask(t)))
                     .SelectMany(t => t).ToArray();

            throw new System.NotImplementedException();
        }
	}
}

