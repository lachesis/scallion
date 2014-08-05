using System;
using OpenSSL.Core;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Linq;

namespace scallion
{
	public class GpgToolConfig : ToolConfig
	{

		public GpgToolConfig(string pattern) : base(pattern) { }

		public override TimeSpan PredictRuntime(long hashRate)
		{
			// 4 = log_2(16) [for hex address]
			var hashes_per_win = _regex.GenerateAllPatternsForRegex().Select(t=>Math.Pow(2,4*t.Count(q=>q!='.') - 1)).Sum();
			long runtime_sec = (long)(hashes_per_win / hashRate);
			return TimeSpan.FromSeconds(runtime_sec);
		}

		public override bool CheckMatch(RSAWrapper rsa)
		{
			return _regex.DoesHashMatchPattern(rsa.GPG_fingerprint_string);
		}

		protected override RegexPattern CreateRegexPattern(string pattern)
		{
			return new RegexPattern(pattern, 40, "0123456789abcdef");
		}

		protected override IList<BitmaskPatternsTuple> GenerateBitmaskPatterns()
		{
			Func<string, byte[]> hexToBytes = (hex) => {
				return Enumerable.Range(0, hex.Length)
					      .Where(x => x % 2 == 0)
						  .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
						  .ToArray();
			};

			return _regex.GeneratePatternsForGpu(9)
					.GroupBy(i => _regex.ConvertPatternToBitmask(i))
					.Select(i => {
						uint[] bitmask = TorBase32.ToUIntArray(hexToBytes(
                            Regex.Replace(i.Key.ToLower(), "[^.]", "f").Replace(".", "0")
						).PadLeft(20)); // 20 bytes = 40 hex chars = 160 bits

                        return new BitmaskPatternsTuple(
                            bitmask,
                            i.Select(j => TorBase32.ToUIntArray(hexToBytes(j.Replace('.', '0')).PadLeft(20)))
                        );
                    })
					.ToList();
		}

		public override uint MinimumExponent {
			get {
				return 0x80010001;
			}
		}

		public override uint MaximumExponent {
			get {
				return 0xFFFFFFFF;
			}
		}

		public override byte[] GetPublicKeyData(RSAWrapper rsa, out int exp_index)
		{
			return rsa.GPG_v4Packet(out exp_index);
		}

		public override string PrivateKeyToString(RSAWrapper rsa)
		{
			return rsa.GPG_privkey_export;
		}

		public override string HashToString(RSAWrapper rsa)
		{
			return rsa.GPG_fingerprint_string;
		}
	}
}

