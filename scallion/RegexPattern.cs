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
        public RegexPattern(string regex, int outputLength, string validCharacters)
        {
			regex = regex.ToLower();
            _regexPatterns = regex.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(i => new SingleRegexPattern(i, outputLength, validCharacters))
                .ToArray();
            _regex = new Regex(regex);
        }
        
		public IEnumerable<string> GenerateAllPatternsForRegex()
        {
            return _regexPatterns.SelectMany(i => i.GenerateAllPatternsForRegex()).Distinct();
        }
        public IEnumerable<string> GeneratePatternsForGpu(int minCharacters)
        {
            return _regexPatterns
                .SelectMany(i => i.GeneratePatternsForGpu(minCharacters))
                .Distinct();
        }
		[ObsoleteAttribute("This property is obsolete. Use ConvertPatternToBitmask instead.", false)] 
        public IEnumerable<string> GeneratePatternBitmasksForGpu(int minCharacters)
        {
			return GeneratePatternsForGpu(minCharacters)
                .Select(i => ConvertPatternToBitmask(i))
                .Distinct();
        }
        private static Regex _notDotRegex = new Regex("[^.]"); 
        public string ConvertPatternToBitmask(string pattern)
        {
            return _notDotRegex.Replace(pattern, "x");
        }
        public bool DoesHashMatchPattern(string hash)
        {
            return _regex.IsMatch(hash);
        }

        private class SingleRegexPattern
        {
            private readonly List<char[]> _parsedRegex = new List<char[]>();
            //private readonly Regex _regex;
            private readonly int _outputLength;
            public SingleRegexPattern(string regex, int outputLength, string validCharacters)
            {
                _outputLength = outputLength;

                // check for invalid characters in given regex
                Regex invalidMarkupRegex = new Regex("[^" + validCharacters + @"\^\$\[\]\.\\]");
                var invalidMatch = invalidMarkupRegex.Match(regex);
                if (invalidMatch.Success)
                    throw new ApplicationException(string.Format("Unsupported character in Regex: '{0}'",
                        invalidMatch.Value));

                //create the regexRegex
                Regex regexRegex = new Regex(string.Format(@"\[[{0}]*\]|[{0}.]", validCharacters));

				// parse ^ for beginning and strip it
				regex = regex.Trim();
				if (regex.StartsWith("^"))
					regex = regex.Substring(1);
                // parse $ for end and pad it
				regex = regex.Trim();
                if (regex.EndsWith("$"))
                    regex = regex.Substring(0, regex.Length - 1).PadLeft(outputLength, '.');
                //to lower and replace character classes
                int trash;
                regex = regex
                    .ToLower()
                    .Replace(@"\D", validCharacters.Where(i => !int.TryParse(i.ToString(), out trash)).ToDelimitedString(""))
                    .Replace(@"\w", ".")
                    .Replace(@"\d", validCharacters.Where(i => int.TryParse(i.ToString(), out trash)).ToDelimitedString(""));
                //validate regex
                if (regexRegex.Matches(regex).Cast<Match>().Sum(i => i.Value.Length) != regex.Length)
                    throw new ApplicationException("The passed regex string is not valid!");
                //_regex = new Regex(regex);
                //parse regex
                _parsedRegex =
                    regexRegex.Matches(regex)
                    .Cast<Match>()
                    .Select(match => match.Groups[0].Value.ToArray().Where(i => i != '[' && i != ']').ToArray())
                    .ToList();
                //make sure the parsed regex is 16 chars long
                while (_parsedRegex.Count < outputLength) _parsedRegex.Add(new char[] { '.' });
            }
            public IEnumerable<string> GenerateAllPatternsForRegex()
            {
                return GeneratePatterns(_parsedRegex);
            }
            private IEnumerable<string> GeneratePatterns(IEnumerable<char[]> remainingPattern)
            {
                if (!remainingPattern.Any()) yield return "";
                else
                    foreach (string s in GeneratePatterns(remainingPattern.Skip(1)))
                        foreach (char c in remainingPattern.First())
                            yield return c + s;
            }
            public IEnumerable<string> GeneratePatternsForGpu(int minCharacters)
            {
                List<char[]> pattern = (new string('.', _outputLength)).ToArray()
                    .Select(i => new char[] { i }).ToList();
                var charClasses = _parsedRegex.Enumerate().OrderBy(i => i.Value[0] == '.' ? 666 : i.Value.Length).ToArray();
                for (int i = 0; i < minCharacters; i++)
                {
                    pattern[charClasses[i].Key] = charClasses[i].Value;
                }
                return GeneratePatterns(pattern);
            }
        }
    }
}
