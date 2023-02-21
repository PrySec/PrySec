namespace PrySec.Core.Native.Posix;

public static partial class PosixErrorCodes
{
    public static string GetPosixErrorMessage(int errno) => 
        _errorCodes.TryGetValue(errno, out PosixErrorCode error) 
            ? error.ToString() 
            : $"Unknown errno: {errno}";

    public static PosixErrorCode GetPosixError(int errno) =>
        _errorCodes.TryGetValue(errno, out PosixErrorCode error)
            ? error
            : new PosixErrorCode("Unknown error", errno, "Unknown errno");
}
