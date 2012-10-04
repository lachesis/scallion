using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OpenTK.Compute.CL10;

namespace scallion
{
    public static unsafe class OpenGLInfo
    {
        private static readonly void* NullPtr = IntPtr.Zero.ToPointer();
        private static readonly IntPtr Null = IntPtr.Zero;
        private static void CheckError(int err)
        {
            CheckError((ErrorCode)err, "");
        }
        private static void CheckError(int err, string msg, params object[] args)
        {
            CheckError((ErrorCode)err, msg, args);
        }
        private static void CheckError(ErrorCode err, string msg, params object[] args)
        {
            if (err != ErrorCode.Success)
            {
                msg = string.Format(msg, args);
                throw new System.InvalidOperationException(msg + string.Format(" ErrorCode:'{0}'", err));
            }
        }
        public static string GetDeviceInfoString(IntPtr deviceId, DeviceInfo paramName)
        {
            //get size
            uint parmSize;
            CheckError(CL.GetDeviceInfo(deviceId, paramName, Null, Null, (IntPtr*)&parmSize));
            //get value
            byte[] value = new byte[parmSize];
            fixed (byte* valuePtr = value)
            {
                CheckError(CL.GetDeviceInfo(deviceId, paramName, new IntPtr(&parmSize), new IntPtr(valuePtr), (IntPtr*)NullPtr));
            }
            return Encoding.ASCII.GetString(value);
        }
        public static T GetDeviceInfo<T>(IntPtr deviceId, DeviceInfo paramName) where T : struct
        {
            T ret = default(T);
            CheckError(CL.GetDeviceInfo<T>(deviceId, paramName, new IntPtr(sizeof(IntPtr)), ref ret, (IntPtr*)NullPtr));
            return ret;
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
        public struct FullDeviceInfo
        {
            public IntPtr DeviceId;
            public IntPtr PlatformId;
            public string Name;
            public string[] Extensions;
            public uint MaxComputeUnits;
            public bool Available;
            public bool CompilerAvailable;
            public ulong GlobalMemSize;
            public uint MaxConstantArgs;
            public uint MaxConstantBufferSize;
            public ulong MaxMemAllocSize;
            public uint MaxParameterSize;
            public uint MaxWorkGroupSize;
            public uint MaxWorkItemDimensions;
            public string Profile;
            public DeviceTypeFlags DeviceType;
            public string Vendor;
            public string DriverVersion;
        }
        public static IEnumerable<FullDeviceInfo> GetFullDeviceInfo()
        {
            return GetFullDeviceInfo(GetPlatformIds().SelectMany(i => GetDeviceIds(i, DeviceTypeFlags.DeviceTypeAll)));
        }
        public static IEnumerable<FullDeviceInfo> GetFullDeviceInfo(IEnumerable<IntPtr> deviceIds)
        {
            return deviceIds
                .Select(i =>
                    new FullDeviceInfo()
                    {
                        DeviceId = i,
                        Name = GetDeviceInfoString(i, DeviceInfo.DeviceName),
                        Available = GetDeviceInfo<Bool>(i, DeviceInfo.DeviceAvailable) == Bool.True,
                        CompilerAvailable = GetDeviceInfo<Bool>(i, DeviceInfo.DeviceCompilerAvailable) == Bool.True,
                        DeviceType = GetDeviceInfo<DeviceTypeFlags>(i, DeviceInfo.DeviceType),
                        DriverVersion = GetDeviceInfoString(i, DeviceInfo.DriverVersion),
                        Extensions = GetDeviceInfoString(i, DeviceInfo.DeviceExtensions).Split(new char[] { ' ' }),
                        GlobalMemSize = GetDeviceInfo<ulong>(i, DeviceInfo.DeviceGlobalMemSize),
                        MaxComputeUnits = GetDeviceInfo<uint>(i, DeviceInfo.DeviceMaxComputeUnits),
                        MaxConstantArgs = GetDeviceInfo<uint>(i, DeviceInfo.DeviceMaxConstantArgs),
                        MaxConstantBufferSize = GetDeviceInfo<uint>(i, DeviceInfo.DeviceMaxConstantBufferSize),
                        MaxMemAllocSize = GetDeviceInfo<ulong>(i, DeviceInfo.DeviceMaxMemAllocSize),
                        MaxParameterSize = GetDeviceInfo<uint>(i, DeviceInfo.DeviceMaxParameterSize),
                        MaxWorkGroupSize = GetDeviceInfo<uint>(i, DeviceInfo.DeviceMaxWorkGroupSize),
                        MaxWorkItemDimensions = GetDeviceInfo<uint>(i, DeviceInfo.DeviceMaxWorkItemDimensions),
                        PlatformId = GetDeviceInfo<IntPtr>(i, DeviceInfo.DevicePlatform),
                        Profile = GetDeviceInfoString(i, DeviceInfo.DeviceProfile),
                        Vendor = GetDeviceInfoString(i, DeviceInfo.DeviceVendor)
                    })
                .ToArray();
        }
        public static string GetPlatformInfoString(IntPtr platformId, PlatformInfo paramName)
        {
            //get size
            uint parmSize;
            CheckError(CL.GetPlatformInfo(platformId, paramName, Null, Null, (IntPtr*)&parmSize));
            //get value
            byte[] value = new byte[parmSize];
            fixed(byte* valuePtr = value)
            {
                CheckError(CL.GetPlatformInfo(platformId, paramName, new IntPtr(&parmSize), new IntPtr(valuePtr), (IntPtr*)NullPtr));
            }
            return Encoding.ASCII.GetString(value);
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
        public struct FullPlatformInfo
        {
            public string Profile;
            public string Version;
            public string Name;
            public string Vendor;
            public string[] Extensions;
            public IntPtr PlatformId;
        }
        public static IEnumerable<FullPlatformInfo> GetFullPlatformInfo()
        {
            return GetFullPlatformInfo(GetPlatformIds());
        }
        public static IEnumerable<FullPlatformInfo> GetFullPlatformInfo(IEnumerable<IntPtr> platformIds)
        {
            return platformIds
                .Select(i => new FullPlatformInfo()
                    {
                        PlatformId = i,
                        Profile = GetPlatformInfoString(i, PlatformInfo.PlatformName),
                        Name = GetPlatformInfoString(i, PlatformInfo.PlatformName),
                        Extensions = GetPlatformInfoString(i, PlatformInfo.PlatformExtensions).Split(new char[] { ' ' }),
                        Vendor = GetPlatformInfoString(i, PlatformInfo.PlatformVendor),
                        Version = GetPlatformInfoString(i, PlatformInfo.PlatformVersion)
                    })
                .ToArray();
        }
    }
}
