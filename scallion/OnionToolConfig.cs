using System;
using System.Collections.Generic;
using System.Linq;

namespace scallion
{
	public class OnionToolConfig : ToolConfig
	{

        public OnionToolConfig(string pattern) : base(pattern) { }

		protected override double PredictRuntimeInSeconds(long hashRate)
        {
			// 5 = log_2(32) [for base 32 onion address]
			var hashes_per_win = _regex.GenerateAllPatternsForRegex().Select(t=>Math.Pow(2,5*t.Count(q=>q!='.') - 1)).Sum();
			return (long)(hashes_per_win / hashRate);
        }

        public override bool CheckMatch(RSAWrapper rsa)
        {
			return _regex.DoesHashMatchPattern(rsa.OnionHash);
        }

        protected override RegexPattern CreateRegexPattern(string pattern)
        {
            return new RegexPattern(pattern, 16, "abcdefghijklmnopqrstuvwxyz234567");
        }

        protected override IList<BitmaskPatternsTuple> GenerateBitmaskPatterns()
        {
            return _regex.GeneratePatternsForGpu(7)
                .GroupBy(i => _regex.ConvertPatternToBitmask(i))
                .Select(i => new BitmaskPatternsTuple(
                    TorBase32.ToUIntArray(TorBase32.CreateBase32Mask(i.Key)),
                    i.Select(j => TorBase32.ToUIntArray(TorBase32.FromBase32Str(j.Replace('.', 'a'))))
                ))
                .ToList();
        }

		public override uint MinimumExponent {
			get {
				return 0x01010001;
			}
		}

		public override uint MaximumExponent {
			get {
				return 0x7FFFFFFF;
			}
		}

		public override byte[] GetPublicKeyData(RSAWrapper rsa, out int exp_index)
		{
			byte[] der = rsa.DER;
			exp_index = der.Length - Util.GetDerLen(MinimumExponent);
			return der;
		}

		public override string PrivateKeyToString(RSAWrapper rsa)
		{
			return rsa.Rsa.PrivateKeyAsPEM;
		}

		public override string HashToString(RSAWrapper rsa)
		{
			return rsa.OnionHash + ".onion";
		}
	}
}

