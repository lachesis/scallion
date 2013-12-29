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
			return _regex.GeneratePatternsForGpu(7)
					.GroupBy(i => _regex.ConvertPatternToBitmak(i))
					.Select(i => {
                        byte[] unpaddedBitmask = BigNumber.FromHexString(
                            Regex.Replace(i.Key.ToLower(), "[^.]", "f").Replace(".", "0")
                        ).ToBytes();

                        byte[] paddedBitmask = new byte[20];
                        Array.Copy(unpaddedBitmask, 0, paddedBitmask, paddedBitmask.Length - unpaddedBitmask.Length, unpaddedBitmask.Length);

                        var bitmask = TorBase32.ToUIntArray(paddedBitmask);
                        return new BitmaskPatternsTuple(
                            bitmask,
                            i.Select(j => TorBase32.ToUIntArray(BigNumber.FromHexString(j.Replace('.', 'f')).ToBytes()))
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

