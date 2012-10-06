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
			ContextId = CL.CreateContext((ContextProperties*)null, 1, (IntPtr*)DeviceId.ToPointer(), IntPtr.Zero, IntPtr.Zero, &error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling CreateContext");
			CommandQueueId = CL.CreateCommandQueue(ContextId, DeviceId, (CommandQueueFlags)0, &error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling CreateCommandQueue");
		}
		public IntPtr CreateAndCompileProgram(string source)
		{
			ErrorCode error;
			IntPtr programId;
			programId = CL.CreateProgramWithSource(ContextId, 1, new string[] { source }, null, &error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling CreateProgramWithSource");
			error = (ErrorCode)CL.BuildProgram(programId, 0, (IntPtr[])null, null, IntPtr.Zero, IntPtr.Zero);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling BuildProgram");
			return programId;
		}
		public CLKernel CreateKernel(IntPtr programId, string kernelName)
		{
			return new CLKernel(DeviceId, Device.Is64Bit, ContextId, CommandQueueId, programId, kernelName);
		}
		public CLBuffer<T> CreateBuffer<T>(MemFlags memFlags, T[] data) where T : struct
		{
			return new CLBuffer<T>(Device.Is64Bit, ContextId, CommandQueueId, memFlags, data);
		}
	}
	public unsafe class CLBuffer<T> : IDisposable where T : struct
	{
		public readonly GCHandle Handle;
		public readonly IntPtr BufferId;
		public readonly IntPtr CommandQueueId;
		public readonly bool IsDevice64Bit;
		public readonly ulong BufferSize;
		public CLBuffer(bool isDevice64Bit, IntPtr contextId, IntPtr commandQueueId, MemFlags memFlags, T[] data)
		{
			IsDevice64Bit = isDevice64Bit;
			CommandQueueId = commandQueueId;
			Handle = GCHandle.Alloc(data);
			ErrorCode error = ErrorCode.Success;
			BufferSize = (ulong)Marshal.SizeOf(typeof(T)) * (ulong)data.Length;
			BufferId = CL.CreateBuffer(contextId, memFlags, new SizeT(BufferSize, IsDevice64Bit), Handle.AddrOfPinnedObject(), &error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling CreateBuffer");
		}

		public void EnqueueWrite()
		{
			ErrorCode error;
			error = (ErrorCode)CL.EnqueueWriteBuffer(CommandQueueId, BufferId, true, new SizeT(0, IsDevice64Bit), new SizeT(0, IsDevice64Bit), 
				Handle.AddrOfPinnedObject(), 0, (IntPtr*)IntPtr.Zero.ToPointer(), (IntPtr*)IntPtr.Zero.ToPointer());
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling EnqueueWriteBuffer");
		}

		public void EnqueueRead()
		{
			ErrorCode error;
			error = (ErrorCode)CL.EnqueueReadBuffer(CommandQueueId, BufferId, true, new SizeT(0, IsDevice64Bit), new SizeT(0, IsDevice64Bit),
				Handle.AddrOfPinnedObject(), 0, (IntPtr*)IntPtr.Zero.ToPointer(), (IntPtr*)IntPtr.Zero.ToPointer());
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling EnqueueReadBuffer");
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
		public readonly bool Is64BitDevice;
		public readonly IntPtr DeviceId;
		public CLKernel(IntPtr deviceId, bool is64BitDevice, IntPtr contextId, IntPtr commandQueueId, IntPtr programId, string kernelName)
		{
			DeviceId = deviceId;
			Is64BitDevice = is64BitDevice;
			ContextId = contextId;
			CommandQueueId = commandQueueId;
			ProgramId = programId;
			KernelName = kernelName;

			ErrorCode error;
			KernelId = CL.CreateKernel(ProgramId, KernelName, out error);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling CreateKernel");

			//error = (ErrorCode)CL.EnqueueNDRangeKernel(hCmdQueue, hKernel, 1, null, &cnDimension, null, 0, null, null);
			//if (error != ErrorCode.Success)
			//    throw new Exception(error.ToString());
		}
		public void EnqueueNDRangeKernel()
		{
			ErrorCode error;
			error = (ErrorCode)CL.EnqueueNDRangeKernel(CommandQueueId, KernelId, 1, null,
				(IntPtr*)((IntPtr)new SizeT(1024*1024, Is64BitDevice)).ToPointer(),
				(IntPtr*)((IntPtr)new SizeT(128, Is64BitDevice)).ToPointer(), 0, null, null);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling EnqueueNDRangeKernel");
		}
		public void SetKernelArgLocal(int argIndex, ulong size)
		{
			ErrorCode error;
			error = (ErrorCode)CL.SetKernelArg(KernelId, argIndex, new SizeT(size, Is64BitDevice), IntPtr.Zero);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling SetKernelArg");
		}
		public void SetKernelArg<T>(int argIndex, T value) where T : struct
		{
			ErrorCode error;
			var handle = GCHandle.Alloc(value);
			ulong size = (ulong)Marshal.SizeOf(typeof(T));
			error = (ErrorCode)CL.SetKernelArg(KernelId, argIndex, new SizeT(size, Is64BitDevice), handle.AddrOfPinnedObject());
			handle.Free();
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling SetKernelArg");
		}
		public void SetKernelArg<T>(int argIndex, CLBuffer<T> value) where T : struct
		{
			ErrorCode error;
			error = (ErrorCode)CL.SetKernelArg(KernelId, argIndex, new SizeT((ulong)sizeof(IntPtr), Is64BitDevice), value.BufferId);
			if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling SetKernelArg");
		}
		public ulong KernelPreferredWorkGroupSizeMultiple
		{
			get
			{
				ErrorCode error;
				SizeT ret = new SizeT(0, Is64BitDevice);
				error = (ErrorCode)CL.GetKernelWorkGroupInfo(KernelId, DeviceId, KernelWorkGroupInfo.KernelPreferredWorkGroupSizeMultiple, new SizeT(ret.Size, Is64BitDevice), ret, (IntPtr*)IntPtr.Zero.ToPointer());
				if (error != ErrorCode.Success) throw new System.InvalidOperationException("Error calling GetKernelWorkGroupInfo");
				return ret.Value;
			}
		}
	}
	public unsafe struct SizeT
	{
		public SizeT(ulong value, bool is64Bit)
		{
			_valueULong = value;
			_valueUInt = unchecked((uint)value);
			_is64Bit = is64Bit;
		}
		public ulong Value { get { return _valueULong; } }
		public bool Is64Bit { get { return _is64Bit; } }
		private ulong _valueULong;
		private uint _valueUInt;
		private bool _is64Bit;
		public ulong Size
		{
			get { return _is64Bit ? (ulong)8 : (ulong)4; }
		}
		public static implicit operator ulong(SizeT sizeT)
		{
			return sizeT._valueULong;
		}
		public static implicit operator IntPtr(SizeT sizeT)
		{
			if (sizeT._is64Bit) return new IntPtr(&sizeT._valueULong);
			else return new IntPtr(&sizeT._valueUInt);
		}
	}
}
