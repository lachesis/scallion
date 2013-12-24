using System;
using System.Collections.Generic;
using System.Linq;

namespace scallion
{
	public class BitmaskPatternsTuple
	{
        public BitmaskPatternsTuple() { }
        public BitmaskPatternsTuple(uint[] bitmask, IEnumerable<uint[]> patterns)
        {
            Bitmask = bitmask;
            patterns = Patterns.ToList();
        }
		public uint[] Bitmask;
		public IList<uint[]> Patterns;
	}

    public abstract class ToolConfig
    {
        protected RegexPattern _regex;
        protected IList<BitmaskPatternsTuple> _bitmaskPatterns;
        public ToolConfig(string pattern)
        {
            _regex = CreateRegexPattern(pattern);
            _bitmaskPatterns = GenerateBitmaskPatterns();
        }
        public bool SinglePattern
        {
            get { return BitmaskPatterns.SelectMany(i => i.Patterns).Count() == 1; }
        }
        public IList<BitmaskPatternsTuple> BitmaskPatterns 
        {
            get { return _bitmaskPatterns; } 
        }
        public int NumberOfWords
        {
            get { return BitmaskPatterns[0].Bitmask.Length; }
        }
		public IList<int> NumberOfHashEntriesByMask
		{
			get { return BitmaskPatterns.Select(i => 2).ToList(); } // MAGIC TODO: MAGIC-LESS 
		}
        protected abstract RegexPattern CreateRegexPattern(string pattern);
        public abstract TimeSpan PredictRuntime(int hashRate);
        public abstract bool CheckMatch(RSAWrapper rsa);
        protected abstract IList<BitmaskPatternsTuple> GenerateBitmaskPatterns();

    }
}

