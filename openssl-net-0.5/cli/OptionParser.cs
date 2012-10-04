// Copyright (c) 2006-2007 Frank Laub
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using System;
using System.Collections.Generic;
using System.Text;
using System.Reflection;

namespace OpenSSL.CLI
{
	class Option
	{
		private string name;
		private object value;

		public string Name
		{
			get { return this.name; }
		}

		public object Value
		{
			get { return this.value; }
			set { this.value = value; }
		}

		public Option(string name, object value)
		{
			this.name = name;
			this.value = value;
		}
	}

	class OptionParser
	{
		Dictionary<string, Option> optionsByKeyword = new Dictionary<string,Option>();
		Dictionary<string, Option> optionsByName = new Dictionary<string, Option>();
		List<string> args = new List<string>();

		public OptionParser() { }

		public void AddOption(string keyword, Option option)
		{
			this.optionsByKeyword.Add(keyword, option);
			this.optionsByName.Add(option.Name, option);
		}

		public void AddMultiOption(string[] keywords, Option option) {
			this.optionsByName.Add(option.Name, option);
			foreach (string keyword in keywords) {
				this.optionsByKeyword.Add(keyword, option);
			}
		}

		public void ParseArguments(string[] args)
		{
			for (int i = 1; i < args.Length; i++)
			{
				if (!args[i].StartsWith("-"))
				{
					this.args.Add(args[i]);
					continue;
				}

				if (!this.optionsByKeyword.ContainsKey(args[i]))
					throw new ArgumentOutOfRangeException(args[i], "Option not defined");

				Option option = this.optionsByKeyword[args[i]];
				if (option.Value.GetType() == typeof(bool))
					option.Value = true;
				else if (option.Value.GetType() == typeof(string))
					option.Value = args[++i];
			}
		}

		public List<string> Arguments
		{
			get { return this.args; }
		}

		public object this[string name]
		{
			get { return this.optionsByName[name].Value; }
		}

		public string GetString(string name)
		{
			return (string)this.optionsByName[name].Value; 
		}

		public bool IsSet(string name)
		{
			Option option;
			if (optionsByName.TryGetValue(name, out option)) {
				if (option.Value.GetType() == typeof(bool))
					return (bool)option.Value;
				else if(option.Value.ToString().Length > 0)
					return true;
			}
			return false;
		}
	}
}
