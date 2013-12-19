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
		public static string GenerateKernel(ProgramParameters programParameters, int numberOfMasks, int numberOfHashesPerKey, uint[] Bitmask, uint[] Pattern, int numberOfPatterns, int expIndexInBytes)
		{
			//Read kernel.cl
			StringBuilder builder = new StringBuilder();
			string kernelFile = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + Path.DirectorySeparatorChar + "kernel.cl";
			builder.Append(File.ReadAllText(kernelFile));
			//Replace program parms
			builder.Replace("GENERATED__CONSTANTS", programParameters.CreateDefinesString());
			//replace checking code
			builder.Replace("GENERATED__CHECKING_CODE", GenerateCheckingCode(numberOfMasks, numberOfHashesPerKey, Bitmask, Pattern, numberOfPatterns));
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

		private static string GenerateCheckingCode(int numberOfMasks, int numberOfHashesPerKey, uint[] Bitmask, uint[] Pattern, int numberOfPatterns)
		{
			StringBuilder builder = new StringBuilder();

			// Makes the checking code do a simple 3-word check for a single pattern
			// instead of using the hashtable (about 8% faster)
            if(numberOfMasks == 1 && numberOfHashesPerKey == 1 && numberOfPatterns == 1)
            {
                builder.AppendLine("if(((H[0] & {0}u) == {1}u) && ((H[1] & {2}u) == {3}u) && ((H[2] & {4}u) == {5}u))",
                    Bitmask[0],Pattern[0], Bitmask[1],Pattern[1], Bitmask[2],Pattern[2] );
                builder.AppendLine("        Results[get_local_id(0) % ResultsArraySize] = exp;");
            }
            else
            {
                for (int m = 0; m < numberOfMasks; m++)
                {
                    builder.AppendLine("BEGIN_MASK({0})", m);
                    builder.AppendLines(Util.Range(numberOfHashesPerKey)
                        .Select(i => string.Format("    CHECK_HASH({0})", i)));
                }
            }
			return builder.ToString();
		}
	}
}
