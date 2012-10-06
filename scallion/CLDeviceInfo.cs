using System;
using OpenTK.Compute.CL10;
using System.Text;
using System.Linq;
using System.Xml.Serialization;
namespace scallion
{
	public unsafe class CLDeviceInfo
	{
		public readonly IntPtr DeviceId;
		public readonly uint  AddressBits;
		public CLDeviceInfo(IntPtr deviceId)
		{
			DeviceId = deviceId;
			AddressBits = GetDeviceInfo_uint(DeviceInfo.DeviceAddressBits);
		}
		public bool Is64Bit
		{
			get { return AddressBits == 64; }
		}
		public static IntPtr[] GetDeviceIds()
		{
			return GetPlatformIds()
				.SelectMany(i=>GetDeviceIds(i, DeviceTypeFlags.DeviceTypeAll))
				.ToArray();
		}
		
		public static IntPtr[] GetDeviceIds(IntPtr platformId, DeviceTypeFlags deviceType)
        {
            //get numOfPlatforms
            uint num;
            CheckError(CL.GetDeviceIDs(platformId, deviceType, 0, (IntPtr*)NullPtr, &num));
            //get platforms
            IntPtr[] ids = new IntPtr[num];
            fixed (IntPtr* idsPtr = ids)
            {
                CheckError(CL.GetDeviceIDs(platformId, deviceType, num, idsPtr, (uint*)NullPtr));
            }
            return ids;
        }
		
		public static IntPtr[] GetPlatformIds()
        {
            //get numOfPlatforms
            uint numOfPlatforms;
            CheckError(CL.GetPlatformIDs(0, (IntPtr*)NullPtr, &numOfPlatforms));
            //get platforms
            IntPtr[] platformsIds = new IntPtr[numOfPlatforms];
            fixed(IntPtr* platformsIdsPtr = platformsIds)
            {
                CheckError(CL.GetPlatformIDs(numOfPlatforms, platformsIdsPtr, (uint*)NullPtr));
            }
            return platformsIds;
        }
		
		public bool Available
		{
			get { return (bool)GetDeviceInfo_bool(DeviceInfo.DeviceAvailable);}
		}
		
		public bool CompilerAvailable
		{
			get { return (bool)GetDeviceInfo_bool(DeviceInfo.DeviceCompilerAvailable);}
		}
		
		public bool EndianLittle
		{
			get { return (bool)GetDeviceInfo_bool(DeviceInfo.DeviceEndianLittle);}
		}
		
		public bool ErrorCorrectionSupport
		{
			get { return (bool)GetDeviceInfo_bool(DeviceInfo.DeviceErrorCorrectionSupport);}
		}
		
		public DeviceExecCapabilitiesFlags ExecutionCapabilities
		{
			get { return (DeviceExecCapabilitiesFlags)GetDeviceInfo_long(DeviceInfo.DeviceExecutionCapabilities);}
		}
		
		public string Extensions
		{
			get { return (string)GetDeviceInfo_string(DeviceInfo.DeviceExtensions);}
		}
		
		public ulong GlobalMemCacheSize
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceGlobalMemCacheSize);}
		}
		
		public DeviceMemCacheType GlobalMemCacheType
		{
			get { return (DeviceMemCacheType)GetDeviceInfo_long(DeviceInfo.DeviceGlobalMemCacheType);}
		}
		
		public uint GlobalMemCachelineSize
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceGlobalMemCachelineSize);}
		}
		
		public ulong GlobalMemSize
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceGlobalMemSize);}
		}
		
		public bool ImageSupport
		{
			get { return (bool)GetDeviceInfo_bool(DeviceInfo.DeviceImageSupport);}
		}
		
		public ulong Image2dMaxHeight
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceImage2dMaxHeight);}
		}
		
		public ulong Image2dMaxWidth
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceImage2dMaxWidth);}
		}
		
		public ulong Image3dMaxDepth
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceImage3dMaxDepth);}
		}
		
		public ulong Image3dMaxHeight
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceImage3dMaxHeight);}
		}
		
		public ulong Image3dMaxWidth
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceImage3dMaxWidth);}
		}
		
		public ulong LocalMemSize
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceLocalMemSize);}
		}
		
		public DeviceLocalMemType LocalMemType
		{
			get { return (DeviceLocalMemType)GetDeviceInfo_long(DeviceInfo.DeviceLocalMemType);}
		}
		
		public uint MaxClockFrequency
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMaxClockFrequency);}
		}
		
		public uint MaxComputeUnits
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMaxComputeUnits);}
		}
		
		public uint MaxConstantArgs
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMaxConstantArgs);}
		}
		
		public ulong MaxConstantBufferSize
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceMaxConstantBufferSize);}
		}
		
		public ulong MaxMemAllocSize
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceMaxMemAllocSize);}
		}
		
		public ulong MaxParameterSize
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceMaxParameterSize);}
		}
		
		public uint MaxReadImageArgs
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMaxReadImageArgs);}
		}
		
		public uint MaxSamplers
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMaxSamplers);}
		}
		
		public ulong MaxWorkGroupSize
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceMaxWorkGroupSize);}
		}
		
		public uint MaxWorkItemDimensions
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMaxWorkItemDimensions);}
		}
		
		public uint MaxWriteImageArgs
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMaxWriteImageArgs);}
		}
		
		public uint MemBaseAddrAlign
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMemBaseAddrAlign);}
		}
		
		public uint MinDataTypeAlignSize
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceMinDataTypeAlignSize);}
		}
		
		public string Name
		{
			get { return (string)GetDeviceInfo_string(DeviceInfo.DeviceName);}
		}
		
		public uint PreferredVectorWidthChar
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DevicePreferredVectorWidthChar);}
		}
		
		public uint PreferredVectorWidthShort
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DevicePreferredVectorWidthShort);}
		}
		
		public uint PreferredVectorWidthInt
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DevicePreferredVectorWidthInt);}
		}
		
		public uint PreferredVectorWidthLong
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DevicePreferredVectorWidthLong);}
		}
		
		public uint PreferredVectorWidthFloat
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DevicePreferredVectorWidthFloat);}
		}
		
		public uint PreferredVectorWidthDouble
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DevicePreferredVectorWidthDouble);}
		}
		
		public string Profile
		{
			get { return (string)GetDeviceInfo_string(DeviceInfo.DeviceProfile);}
		}
		
		public ulong ProfilingTimerResolution
		{
			get { return (ulong)GetDeviceInfo_ulong(DeviceInfo.DeviceProfilingTimerResolution);}
		}
		
		public DeviceTypeFlags Type
		{
			get { return (DeviceTypeFlags)GetDeviceInfo_ulong(DeviceInfo.DeviceType);}
		}
		
		public string Vendor
		{
			get { return (string)GetDeviceInfo_string(DeviceInfo.DeviceVendor);}
		}
		
		public uint VendorId
		{
			get { return (uint)GetDeviceInfo_uint(DeviceInfo.DeviceVendorId);}
		}
		
		public string Version
		{
			get { return (string)GetDeviceInfo_string(DeviceInfo.DeviceVersion);}
		}
		
		private uint GetDeviceInfo_uint(DeviceInfo paramName)
		{
			uint ret = default(uint);
			CheckError(CL.GetDeviceInfo<uint>(DeviceId, paramName, IntSizePtr, ref ret, (IntPtr*)NullPtr));
			return ret;
		}
		private long GetDeviceInfo_long(DeviceInfo paramName)
		{
			long ret = default(long);
			CheckError(CL.GetDeviceInfo<long>(DeviceId, paramName, LongSizePtr, ref ret, (IntPtr*)NullPtr));
			return ret;
		}
		private ulong GetDeviceInfo_ulong(DeviceInfo paramName)
		{
			ulong ret = default(ulong);
			CheckError(CL.GetDeviceInfo<ulong>(DeviceId, paramName, LongSizePtr, ref ret, (IntPtr*)NullPtr));
			return ret;
		}
		private bool GetDeviceInfo_bool(DeviceInfo paramName)
		{
			uint ret = default(uint);
			CheckError(CL.GetDeviceInfo<uint>(DeviceId, paramName, IntSizePtr, ref ret, (IntPtr*)NullPtr));
			return (Bool)ret == Bool.True;
		}
		private ulong GetDeviceInfo_size_t(DeviceInfo paramName)
		{
			if(AddressBits == 32) return (ulong)GetDeviceInfo_uint(paramName);
			else return GetDeviceInfo_ulong(paramName);
		}
		private string GetDeviceInfo_string(DeviceInfo paramName)
        {
            //get size
            uint parmSize;
            CheckError(CL.GetDeviceInfo(DeviceId, paramName, Null, Null, (IntPtr*)&parmSize));
            //get value
            byte[] value = new byte[parmSize];
            fixed (byte* valuePtr = value)
            {
                CheckError(CL.GetDeviceInfo(DeviceId, paramName, new IntPtr(&parmSize), new IntPtr(valuePtr), (IntPtr*)NullPtr));
            }
			return Encoding.ASCII.GetString(value).Trim('\0');
        }
		private static void CheckError(int err)
        {
			if ((ErrorCode)err != ErrorCode.Success)
			{
				throw new System.InvalidOperationException(string.Format(" ErrorCode:'{0}'", err));
			}
        }
		private static readonly void* NullPtr = IntPtr.Zero.ToPointer();
        private static readonly IntPtr Null = IntPtr.Zero;
		private static readonly IntPtr IntSizePtr = new IntPtr(sizeof(int));
		private static readonly IntPtr LongSizePtr = new IntPtr(sizeof(long));
	}
}
