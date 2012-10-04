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
        public static string GetDeviceInfoString(IntPtr platformId, DeviceInfo paramName)
        {
            //get size
            uint parmSize;
            CheckError(CL.GetDeviceInfo(platformId, paramName, Null, Null, (IntPtr*)&parmSize));
            //get value
            byte[] value = new byte[parmSize];
            fixed (byte* valuePtr = value)
            {
                CheckError(CL.GetDeviceInfo(platformId, paramName, new IntPtr(&parmSize), new IntPtr(valuePtr), (IntPtr*)NullPtr));
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
