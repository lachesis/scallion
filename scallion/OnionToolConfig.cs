using System;
using System.Collections.Generic;
using System.Linq;

namespace scallion
{
	public class OnionToolConfig : ToolConfig
	{

        public OnionToolConfig(string pattern) : base(pattern) { }

		public override TimeSpan PredictRuntime(long hashRate)
        {
			// 5 = log_2(32) [for base 32 onion address]
			var hashes_per_win = _regex.GenerateAllPatternsForRegex().Select(t=>Math.Pow(2,5*t.Count(q=>q!='.') - 1)).Sum();
			long runtime_sec = (long)(hashes_per_win / hashRate);
			return TimeSpan.FromSeconds(runtime_sec);
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
                .GroupBy(i => _regex.ConvertPatternToBitmak(i))
                .Select(i => new BitmaskPatternsTuple(
                    TorBase32.ToUIntArray(TorBase32.CreateBase32Mask(i.Key)),
                    i.Select(j => TorBase32.ToUIntArray(TorBase32.FromBase32Str(j.Replace('.', 'a'))))
                ))
                .ToList();
            /*
            //Create Hash Table
            uint[] dataArray;
            ushort[] hashTable;
            uint[][] all_patterns;
            int max_items_per_key = 0;
            {
                Func<uint[], ushort> fnv =
                    (pattern_arr) =>
                    {
                        uint f = Util.FNVHash(pattern_arr[0], pattern_arr[1], pattern_arr[2]);
                        f = ((f >> 10) ^ f) & (uint)1023;
                        return (ushort)f;
                    };
                all_patterns = rp.GenerateOnionPatternsForGpu(7)
                    .Select(i => TorBase32.ToUIntArray(TorBase32.FromBase32Str(i.Replace('.', 'a'))))
                    .ToArray();
                var gpu_dict_list = all_patterns
                    .Select(i => new KeyValuePair<ushort, uint>(fnv(i), Util.FNVHash(i[0], i[1], i[2])))
                    .GroupBy(i => i.Key)
                    .OrderBy(i => i.Key)
                    .ToList();

                dataArray = gpu_dict_list.SelectMany(i => i.Select(j => j.Value)).ToArray();
                hashTable = new ushort[1024]; //item 1 index, item 2 length
                int currIndex = 0;
                foreach (var item in gpu_dict_list)
                {
                    int len = item.Count();
                    hashTable[item.Key] = (ushort)currIndex;
                    currIndex += len;
                    if (len > max_items_per_key) max_items_per_key = len;
                }

                Console.WriteLine("Putting {0} patterns into {1} buckets.", currIndex, gpu_dict_list.Count);
            }
            */
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
	}
}

