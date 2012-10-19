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
		public static string GenerateKernel(ProgramParameters programParameters, int numberOfMasks, int numberOfHashesPerKey)
		{
			//Read kernel.cl
			StringBuilder builder = new StringBuilder();
			string kernelFile = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + Path.DirectorySeparatorChar + "kernel.cl";
			builder.Append(File.ReadAllText(kernelFile));
			//Replace program parms
			builder.Replace("GENERATED__CONSTANTS", programParameters.CreateDefinesString());
			//replace checking code
			builder.Replace("GENERATED__CHECKING_CODE", GenerateCheckingCode(numberOfMasks, numberOfHashesPerKey));
			//Return generated kernel
			return builder.ToString();
		}
		private static string GenerateCheckingCode(int numberOfMasks, int numberOfHashesPerKey)
		{
			StringBuilder builder = new StringBuilder();
			for (int m = 0; m < numberOfMasks; m++)
			{
				builder.AppendLine("BEGIN_MASK({0})", m);
				builder.AppendLines(Util.Range(numberOfHashesPerKey)
					.Select(i => string.Format("    CHECK_HASH({0})", i)));
			}
			return builder.ToString();
		}
	}
}
