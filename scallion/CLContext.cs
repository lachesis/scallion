using System;
using System.Collections.Generic;
using System.Linq;
using OpenTK.Compute.CL10;
using System.Text;
using System.Runtime.InteropServices;

namespace scallion
{
	public unsafe class CLContext
	{
		public readonly IntPtr DeviceId;
		public readonly CLDeviceInfo Device;
		public readonly IntPtr ContextId;
		public readonly IntPtr CommandQueueId;
		public unsafe CLContext(IntPtr deviceId)
		{
			DeviceId = deviceId;
			Device = new CLDeviceInfo(DeviceId);
			ErrorCode error;
			ErrorCode[] errors = new ErrorCode[1];
			ContextId = CL.CreateContext(null, 1, new IntPtr[] { DeviceId }, IntPtr.Zero, IntPtr.Zero, errors);
			if (errors[0] != ErrorCode.Success) throw new System.InvalidOperationException("Error calling CreateContext");
			CommandQueueId = CL.CreateCommandQueue(ContextId, DeviceId, (CommandQueueFlags)0, &error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling CreateCommandQueue: {0}",error));
		}
		public IntPtr CreateAndCompileProgram(string source)
		{
			ErrorCode error;
			IntPtr programId;
			programId = CL.CreateProgramWithSource(ContextId, 1, new string[] { source }, null, &error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling CreateProgramWithSource: {0}",error));
			error = (ErrorCode)CL.BuildProgram(programId, 0, (IntPtr[])null, null, IntPtr.Zero, IntPtr.Zero);
			if (error != ErrorCode.Success)
			{
				uint parmSize;
				CL.GetProgramBuildInfo(programId, DeviceId, ProgramBuildInfo.ProgramBuildLog, IntPtr.Zero, IntPtr.Zero, (IntPtr*)&parmSize);
				byte[] value = new byte[parmSize];
				fixed (byte* valuePtr = value)
				{
					error = (ErrorCode)CL.GetProgramBuildInfo(programId, DeviceId, ProgramBuildInfo.ProgramBuildLog, new IntPtr(&parmSize), new IntPtr(valuePtr), (IntPtr*)IntPtr.Zero.ToPointer());
				}
				if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling GetProgramBuildInfo: {0}",error));
				throw new System.InvalidOperationException(Encoding.ASCII.GetString(value).Trim('\0'));
			}
			return programId;
		}
		public CLKernel CreateKernel(IntPtr programId, string kernelName)
		{
			return new CLKernel(DeviceId, ContextId, CommandQueueId, programId, kernelName);
		}
		public CLBuffer<T> CreateBuffer<T>(MemFlags memFlags, T[] data) where T : struct
		{
			return new CLBuffer<T>(ContextId, CommandQueueId, memFlags, data);
		}
		private bool disposed = false;
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}
		protected virtual void Dispose(bool disposing)
		{
			if (!this.disposed)
			{
				if (disposing) { /*Dispose managed resources*/ }
				CL.ReleaseCommandQueue(CommandQueueId);
				CL.ReleaseContext(ContextId);
			}
		}
		~CLContext()
        {
            Dispose(false);
        }
	}
	public unsafe class CLBuffer<T> : IDisposable where T : struct
	{
		public GCHandle Handle { get; private set; }
		public readonly IntPtr BufferId;
		public readonly IntPtr CommandQueueId;
		public readonly bool IsDevice64Bit;
		public readonly int BufferSize;
		private T[] _data;
		public T[] Data
		{
			get { return _data;}
			set
			{
				if (_data == value) return;
				if (Handle.IsAllocated) Handle.Free();
				_data = value;
				Handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
				if (BufferSize != Marshal.SizeOf(typeof(T)) * _data.Length) throw new System.Exception("Data's length is not the same as the original buffer.");
			}
		}

		public CLBuffer(IntPtr contextId, IntPtr commandQueueId, MemFlags memFlags, T[] data)
		{
			CommandQueueId = commandQueueId;
			ErrorCode error = ErrorCode.Success;
			BufferSize = Marshal.SizeOf(typeof(T)) * data.Length;
			Data = data;
			BufferId = CL.CreateBuffer(contextId, memFlags, new IntPtr(BufferSize), Handle.AddrOfPinnedObject(), &error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling CreateBuffer: {0}",error));
		}

		public void EnqueueWrite()
		{
			ErrorCode error;
			error = (ErrorCode)CL.EnqueueWriteBuffer(CommandQueueId, BufferId, true, new IntPtr(0), new IntPtr(BufferSize), 
				Handle.AddrOfPinnedObject(), 0, (IntPtr*)IntPtr.Zero.ToPointer(), (IntPtr*)IntPtr.Zero.ToPointer());
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling EnqueueWriteBuffer: {0}",error));
		}

		public void EnqueueRead()
		{
			ErrorCode error;
			error = (ErrorCode)CL.EnqueueReadBuffer(CommandQueueId, BufferId, true, new IntPtr(0), new IntPtr(BufferSize),
				Handle.AddrOfPinnedObject(), 0, (IntPtr*)IntPtr.Zero.ToPointer(), (IntPtr*)IntPtr.Zero.ToPointer());
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling EnqueueReadBuffer: {0}",error));
		}

		private bool disposed = false;
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}
		protected virtual void Dispose(bool disposing)
		{
			if (!this.disposed)
			{
				if (disposing) { /*Dispose managed resources*/ }
				// Dispose unmanaged resources.
				CL.ReleaseMemObject(BufferId);
				Handle.Free();
			}
		}
		~CLBuffer()
        {
            Dispose(false);
        }
	}
	public unsafe class CLKernel
	{
		public readonly IntPtr KernelId;
		public readonly IntPtr ContextId;
		public readonly IntPtr CommandQueueId;
		public readonly IntPtr ProgramId;
		public readonly string KernelName;
		public readonly IntPtr DeviceId;
		public CLKernel(IntPtr deviceId, IntPtr contextId, IntPtr commandQueueId, IntPtr programId, string kernelName)
		{
			DeviceId = deviceId;
			ContextId = contextId;
			CommandQueueId = commandQueueId;
			ProgramId = programId;
			KernelName = kernelName;

			ErrorCode error;
			KernelId = CL.CreateKernel(ProgramId, KernelName, out error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling CreateKernel: {0}",error));
		}
		public void EnqueueNDRangeKernel(int globalWorkSize, int localWorkSize)
		{
			ErrorCode error;
			IntPtr pglobalWorkSize = new IntPtr(globalWorkSize);
			IntPtr plocalWorkSize = new IntPtr(localWorkSize);
			error = (ErrorCode)CL.EnqueueNDRangeKernel(CommandQueueId, KernelId, 1, null, &pglobalWorkSize, &plocalWorkSize, 0, null, null);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling EnqueueNDRangeKernel: {0}",error));
		}
		public void SetKernelArgLocal(int argIndex, int size)
		{
			ErrorCode error;
			error = (ErrorCode)CL.SetKernelArg(KernelId, argIndex, new IntPtr(size), IntPtr.Zero);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling SetKernelArg: {0}",error));
		}
		public void SetKernelArg<T>(int argIndex, T value) where T : struct
		{
			ErrorCode error;
			var handle = GCHandle.Alloc(value, GCHandleType.Pinned);
			int size = Marshal.SizeOf(typeof(T));
			error = (ErrorCode)CL.SetKernelArg(KernelId, argIndex, new IntPtr(size), handle.AddrOfPinnedObject());
			handle.Free();
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling SetKernelArg: {0}",error));
		}
		public void SetKernelArg<T>(int argIndex, CLBuffer<T> value) where T : struct
		{
			ErrorCode error;
			IntPtr bufferId = value.BufferId;
			error = (ErrorCode)CL.SetKernelArg(KernelId, argIndex, new IntPtr(sizeof(IntPtr)), new IntPtr(&bufferId));
			if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling SetKernelArg: {0}",error));
		}
		public ulong KernelPreferredWorkGroupSizeMultiple
		{
			get
			{
				ErrorCode error;
				ulong ret = 0;
				error = (ErrorCode)CL.GetKernelWorkGroupInfo(KernelId, DeviceId, KernelWorkGroupInfo.KernelPreferredWorkGroupSizeMultiple, new IntPtr(sizeof(IntPtr)), ref ret, (IntPtr*)IntPtr.Zero.ToPointer());
				if (error != ErrorCode.Success) throw new System.InvalidOperationException(String.Format("Error calling GetKernelWorkGroupInfo: {0}",error));
				return ret;
			}
		}
		private bool disposed = false;
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}
		protected virtual void Dispose(bool disposing)
		{
			if (!this.disposed)
			{
				if (disposing) { /*Dispose managed resources*/ }
				CL.ReleaseContext(ContextId);
			}
		}
		~CLKernel()
        {
            Dispose(false);
        }
	}
}
