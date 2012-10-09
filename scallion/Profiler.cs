using System;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;

namespace scallion
{
	public class Profiler
	{
		struct StopwatchHolder
		{
			public Stopwatch sw;
			public int count;
		}

		Dictionary<string,StopwatchHolder> records;
		public Profiler()
		{
			records = new Dictionary<string, StopwatchHolder>();
		}

		public void StartRegion(string name)
		{
			StopwatchHolder swh;
			if(!records.TryGetValue(name,out swh))
			swh = new StopwatchHolder { count=0, sw=new Stopwatch() };

			swh.count++;
			swh.sw.Start();

			records[name] = swh;
		}

		public void EndRegion(string name)
		{
			StopwatchHolder swh;
			swh = records[name];

			swh.sw.Stop();

			records[name] = swh;
		}

		public string GetSummaryString()
		{
			var sb = new StringBuilder();
			foreach (var kvp in records) {
				long total_ms = kvp.Value.sw.ElapsedMilliseconds;
				int count = kvp.Value.count;
				long rate = total_ms != 0 ? count*1000 / total_ms : 0;
				long msper = count != 0 ? total_ms / count : 0;
				sb.AppendFormat("{0}: {1}ms / {2} ({3}ms, {4}/s)\n",kvp.Key,total_ms,count,msper,rate);
			}
			return sb.ToString();
		}

		public long GetTotalMS(string name)
		{
			return records[name].sw.ElapsedMilliseconds;
		}
	}

}

