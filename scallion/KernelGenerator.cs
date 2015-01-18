using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;

namespace scallion
{
	public class KernelGenerator
	{
		public static string GenerateKernel(ProgramParameters programParameters, ToolConfig toolConfig, int expIndexInBytes)
		{
			//Read kernel.cl
			StringBuilder builder = new StringBuilder();
			string kernelFile = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + Path.DirectorySeparatorChar + "kernel.cl";
			builder.Append(File.ReadAllText(kernelFile));
			//Replace program parms
			builder.Replace("GENERATED__CONSTANTS", programParameters.CreateDefinesString());
			//replace checking code
			builder.Replace("GENERATED__CHECKING_CODE", GenerateCheckingCode(toolConfig));
			// Replace exponent loading code
			builder.Replace("GENERATED__EXP_LOADING_CODE", GenerateExpLoadingCode(expIndexInBytes));
			//Return generated kernel
			return builder.ToString();
		}

		private static string GenerateExpLoadingCode(int expIndexInBytes)
		{
			// Assumes that exponent length is 4 bytes (one uint)
			StringBuilder builder = new StringBuilder();

			int firstWord = expIndexInBytes / 4;
			int offset = expIndexInBytes % 4;
			uint mask1 = 0xFFFFFFFF >> (8 * offset);

			builder.AppendFormat("W[{0}] &= 0x{1:X}u; // AND out the first word\n", firstWord, ~mask1);
			builder.AppendFormat("W[{0}] |= exp >> {1} & 0x{2:x}u; // OR in the first part of the exp\n", firstWord, (8*offset), mask1);
			builder.AppendFormat("W[{0}] &= 0x{1:X}u; // AND out the second word\n", firstWord + 1, mask1);
			builder.AppendFormat("W[{0}] |= exp << {1} & 0x{2:x}u; // OR in the second part of the exp\n", firstWord + 1, (32 - 8*offset), ~mask1);

			return builder.ToString();
		}

		private static string GenerateCheckingCode(ToolConfig toolConfig)
		{
			StringBuilder builder = new StringBuilder();

			BitmaskPatternsTuple bpt = toolConfig.BitmaskPatterns[0];

			// Makes the checking code do a simple 3-word check for a single pattern
			// instead of using the hashtable (about 8% faster)
            if(toolConfig.SinglePattern)
            {
				builder.Append("if(");
				builder.Append(Util.Range(toolConfig.NumberOfWords)
				       .Select(i => {
                           if (bpt.Bitmask[i] == 0 && bpt.Patterns[0][i] == 0)//This optimizes the case where x&0 == 0
                               return null;
                           return String.Format("((H[{0}] & {1}u) == {2}u)", i, bpt.Bitmask[i], bpt.Patterns[0][i]);
                       })
                       .Where(i => i != null)
				       .ToDelimitedString(" && "));
				builder.Append(")\n");

                builder.AppendLine("        Results[get_local_id(0) % ResultsArraySize] = exp;");
            }
            else
            {
                for (int m = 0; m < toolConfig.NumberOfMasks; m++)
                {
                    //TODO: apply optimization "This optimizes the case where x&0 == 0"
					// This chunk of code replaces BEGIN_MASK(m)
                    builder.AppendLine("    //Bitmask #{0}", m);
					builder.AppendFormat("    fnv = fnv_hash_w{0}(", toolConfig.NumberOfWords);
					builder.Append(Util.Range(toolConfig.NumberOfWords)
					       .Select(i => String.Format("(H[{0}] & BitmaskArray[{2}*{1}+{0}])", i, toolConfig.NumberOfWords, m))
					       .ToDelimitedString(","));
					builder.AppendLine(");");
					builder.AppendLine("    fnv10 = (fnv >> 10 ^ fnv) & 1023u;");
					builder.AppendLine("    dataaddr = HashTable[fnv10];");

					builder.AppendLines(Util.Range(toolConfig.MaxKeyCollisions)
					       .Select(i => string.Format("    if(DataArray[dataaddr + {0}] == fnv) Results[get_local_id(0) % ResultsArraySize] = exp;", i)));
                }
            }
			return builder.ToString();
		}
	}
}
