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
		public RegexPattern(string regex)
		{
			regex = regex.ToLower();
			_regex = new Regex(regex);
			if (!Regex.IsMatch(regex, @"(\[[abcdefghijklmnopqrstuvwxyz234567]*\]|[abcdefghijklmnopqrstuvwxyz234567.])*"))
				throw new System.ArgumentException("The passed regex string is not valid!");
			_parsedRegex = 
				Regex.Matches(regex, @"\[[abcdefghijklmnopqrstuvwxyz234567]*\]|[abcdefghijklmnopqrstuvwxyz234567.]")
				.Cast<Match>()
				.Select(match => match.Groups[0].Value.ToArray())
				.ToList();
		}
		public IEnumerable<string> GeneratePatterns()
		{
			return GeneratePatterns(_parsedRegex);
		}
		private IEnumerable<string> GeneratePatterns(IEnumerable<char[]> remainingPattern)
		{
			foreach (string s in GeneratePatterns(remainingPattern.Skip(1)))
				foreach (char c in remainingPattern.First())
					yield return c + s;
		}
		public IEnumerable<string> GeneratePatterns(int minCharacters)
		{
			List<char[]> pattern = "................".ToArray()
				.Select(i => new char[] { i }).ToList();
			var charClasses = _parsedRegex.Enumerate().OrderBy(i => i.Value.Length).ToArray();
			for (int i = 0; i < minCharacters; i++)
			{
				pattern[charClasses[i].Key] = charClasses[i].Value;
			}
			return GeneratePatterns(pattern);
		}
	}
}
