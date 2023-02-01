using System;
using System.Runtime.InteropServices;

namespace PrySec.Core.Native.Posix;

public class PosixException : Exception
{
	public PosixException() : this(Marshal.GetLastPInvokeError()) { }

	public PosixException(int errno) : this(PosixErrorCodes.GetPosixErrorMessage(errno)) { }

    protected PosixException(string message) : base(message) { }
}
