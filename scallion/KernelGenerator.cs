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
		public static string GenerateKernel(ProgramParameters programParameters, int numberOfMasks, int numberOfHashesPerKey, uint[] Bitmask, uint[] Pattern)
		{
			//Read kernel.cl
			StringBuilder builder = new StringBuilder();
			string kernelFile = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + Path.DirectorySeparatorChar + "kernel.cl";
			builder.Append(File.ReadAllText(kernelFile));
			//Replace program parms
			builder.Replace("GENERATED__CONSTANTS", programParameters.CreateDefinesString());
			//replace checking code
			builder.Replace("GENERATED__CHECKING_CODE", GenerateCheckingCode(numberOfMasks, numberOfHashesPerKey, Bitmask, Pattern));
			//Return generated kernel
			return builder.ToString();
		}
		private static string GenerateCheckingCode(int numberOfMasks, int numberOfHashesPerKey, uint[] Bitmask, uint[] Pattern)
		{
			StringBuilder builder = new StringBuilder();

			// Purposely disabled - only a 1% speedup. Feel free to reenable - should work.
			// Makes the checking code do a simple 3-word check for a single pattern
			// Instead of using the hashtable
            if(false && numberOfMasks == 1 && numberOfHashesPerKey == 1)
            {
                builder.AppendLine("if(((H[0] & {0}) == {1}) && ((H[1] & {2}) == {3}) && ((H[2] & {4}) == {5}))",
                    Bitmask[0],Pattern[0], Bitmask[1],Pattern[1], Bitmask[2],Pattern[2] );
                builder.AppendLine("    Results[get_local_id(0) % ResultsArraySize] = exp;");
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
