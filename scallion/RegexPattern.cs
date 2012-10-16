using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace scallion
{
	public class RegexPattern
	{
		private readonly List<char[]> _parsedRegex = new List<char[]>();
		private readonly Regex _regex;
		private readonly Regex _regexRegex = new Regex(@"\[[abcdefghijklmnopqrstuvwxyz234567]*\]|[abcdefghijklmnopqrstuvwxyz234567.]");
		public RegexPattern(string regex)
		{
			regex = regex.ToLower();
			_regex = new Regex(regex);
			if (_regexRegex.Matches(regex).Cast<Match>().Sum(i => i.Value.Length) == regex.Length)
				throw new System.ArgumentException("The passed regex string is not valid!");
			_parsedRegex = 
				_regexRegex.Matches(regex)
				.Cast<Match>()
				.Select(match => match.Groups[0].Value.ToArray())
				.ToList();
		}
		public IEnumerable<string> GenerateAllOnionPatternsForRegex()
		{
			return GenerateOnionPatterns(_parsedRegex);
		}
		private IEnumerable<string> GenerateOnionPatterns(IEnumerable<char[]> remainingPattern)
		{
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
	}
}
