using System;
using System.Collections.Generic;
using System.Linq;

namespace scallion
{
	public class BitmaskPatternsTuple
	{
		public uint[] Bitmask;
		public IList<uint[]> Patterns;
	}

    public abstract class ToolConfig
    {
        protected RegexPattern _regex;
        protected IList<BitmaskPatternsTuple> _bitmaskPatterns;
        public ToolConfig(string pattern)
        {
            _regex = new RegexPattern(pattern);
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
        public abstract TimeSpan PredictRuntime(int hashRate);
        public abstract bool CheckMatch(RSAWrapper rsa);
        public abstract IList<BitmaskPatternsTuple> GenerateBitmaskPatterns();

    }
}

