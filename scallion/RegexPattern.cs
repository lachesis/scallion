using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace scallion
{
	public class RegexPattern
	{
		private readonly SingleRegexPattern[] _regexPatterns;
		private readonly Regex _regex;
		public RegexPattern(string regex)
		{
			_regexPatterns = regex.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
				.Select(i => new SingleRegexPattern(i))
				.ToArray();
			_regex = new Regex(regex);
		}
		/// <summary>
		/// might return the same pattern multiple times. Call .Distinct on the results if you do not want this to be the case
		/// </summary>
		public IEnumerable<string> GenerateAllOnionPatternsForRegex()
		{
			return _regexPatterns.SelectMany(i => i.GenerateAllOnionPatternsForRegex());
		}
		public IEnumerable<string> GenerateOnionPatternsForGpu(int minCharacters)
		{
			return _regexPatterns
				.SelectMany(i => i.GenerateOnionPatternsForGpu(minCharacters))
				.Distinct();
		}
		public IEnumerable<string> GenerateOnionPatternBitmasksForGpu(int minCharacters)
		{
			return _regexPatterns
				.SelectMany(i => i.GenerateOnionPatternBitmasksForGpu(minCharacters))
				.Distinct();
		}
		public bool DoesOnionHashMatchPattern(string onionHash)
		{
			return _regex.IsMatch(onionHash);
		}

		private class SingleRegexPattern
		{
			private readonly List<char[]> _parsedRegex = new List<char[]>();
			private readonly Regex _regex;
			private readonly Regex _regexRegex = new Regex(@"\[[abcdefghijklmnopqrstuvwxyz234567]*\]|[abcdefghijklmnopqrstuvwxyz234567.]");
			public SingleRegexPattern(string regex)
			{
				//to lower and replace character classes
				regex = regex
					.ToLower()
					.Replace(@"\D", "abcdefghijklmnopqrstuvwxyz")
					.Replace(@"\w", ".")
					.Replace(@"\d", "234567");
				//validate regex
				if (_regexRegex.Matches(regex).Cast<Match>().Sum(i => i.Value.Length) != regex.Length)
					throw new System.ArgumentException("The passed regex string is not valid!");
				_regex = new Regex(regex);
				//parse regex
				_parsedRegex =
					_regexRegex.Matches(regex)
					.Cast<Match>()
					.Select(match => match.Groups[0].Value.ToArray().Where(i => i != '[' && i != ']').ToArray())
					.ToList();
				//make sure the parsed regex is 16 chars long
				while (_parsedRegex.Count < 16) _parsedRegex.Add(new char[] { '.' });
			}
			public IEnumerable<string> GenerateAllOnionPatternsForRegex()
			{
				return GenerateOnionPatterns(_parsedRegex);
			}
			private IEnumerable<string> GenerateOnionPatterns(IEnumerable<char[]> remainingPattern)
			{
				if (!remainingPattern.Any()) yield return "";
				else
					foreach (string s in GenerateOnionPatterns(remainingPattern.Skip(1)))
						foreach (char c in remainingPattern.First())
							yield return c + s;
			}
			public IEnumerable<string> GenerateOnionPatternsForGpu(int minCharacters)
			{
				List<char[]> pattern = "................".ToArray()
					.Select(i => new char[] { i }).ToList();
				var charClasses = _parsedRegex.Enumerate().OrderBy(i => i.Value[0] == '.' ? 666 : i.Value.Length).ToArray();
				for (int i = 0; i < minCharacters; i++)
				{
					pattern[charClasses[i].Key] = charClasses[i].Value;
				}
				return GenerateOnionPatterns(pattern);
			}
			public IEnumerable<string> GenerateOnionPatternBitmasksForGpu(int minCharacters)
			{
				Regex notDotRegex = new Regex("[^.]");
				return GenerateOnionPatternsForGpu(minCharacters)
					.Select(i => notDotRegex.Replace(i, "x"))
					.Distinct();
			}
			public bool DoesOnionHashMatchPattern(string onionHash)
			{
				return _regex.IsMatch(onionHash);
			}
		}
	}
}
