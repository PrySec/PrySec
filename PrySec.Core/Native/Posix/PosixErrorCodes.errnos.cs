using System.Collections.Generic;

namespace PrySec.Core.Native.Posix;

public static partial class PosixErrorCodes
{
    private static readonly IReadOnlyDictionary<int, PosixErrorCode> _errorCodes = new Dictionary<int, PosixErrorCode>()
    {
        { PosixErrorCode.EPERM.ErrorCode, PosixErrorCode.EPERM },
        { PosixErrorCode.ENOENT.ErrorCode, PosixErrorCode.ENOENT },
        { PosixErrorCode.ESRCH.ErrorCode, PosixErrorCode.ESRCH },
        { PosixErrorCode.EINTR.ErrorCode, PosixErrorCode.EINTR },
        { PosixErrorCode.EIO.ErrorCode, PosixErrorCode.EIO },
        { PosixErrorCode.ENXIO.ErrorCode, PosixErrorCode.ENXIO },
        { PosixErrorCode.E2BIG.ErrorCode, PosixErrorCode.E2BIG },
        { PosixErrorCode.ENOEXEC.ErrorCode, PosixErrorCode.ENOEXEC },
        { PosixErrorCode.EBADF.ErrorCode, PosixErrorCode.EBADF },
        { PosixErrorCode.ECHILD.ErrorCode, PosixErrorCode.ECHILD },
        { PosixErrorCode.EAGAIN.ErrorCode, PosixErrorCode.EAGAIN },
        { PosixErrorCode.ENOMEM.ErrorCode, PosixErrorCode.ENOMEM },
        { PosixErrorCode.EACCES.ErrorCode, PosixErrorCode.EACCES },
        { PosixErrorCode.EFAULT.ErrorCode, PosixErrorCode.EFAULT },
        { PosixErrorCode.ENOTBLK.ErrorCode, PosixErrorCode.ENOTBLK },
        { PosixErrorCode.EBUSY.ErrorCode, PosixErrorCode.EBUSY },
        { PosixErrorCode.EEXIST.ErrorCode, PosixErrorCode.EEXIST },
        { PosixErrorCode.EXDEV.ErrorCode, PosixErrorCode.EXDEV },
        { PosixErrorCode.ENODEV.ErrorCode, PosixErrorCode.ENODEV },
        { PosixErrorCode.ENOTDIR.ErrorCode, PosixErrorCode.ENOTDIR },
        { PosixErrorCode.EISDIR.ErrorCode, PosixErrorCode.EISDIR },
        { PosixErrorCode.EINVAL.ErrorCode, PosixErrorCode.EINVAL },
        { PosixErrorCode.ENFILE.ErrorCode, PosixErrorCode.ENFILE },
        { PosixErrorCode.EMFILE.ErrorCode, PosixErrorCode.EMFILE },
        { PosixErrorCode.ENOTTY.ErrorCode, PosixErrorCode.ENOTTY },
        { PosixErrorCode.ETXTBSY.ErrorCode, PosixErrorCode.ETXTBSY },
        { PosixErrorCode.EFBIG.ErrorCode, PosixErrorCode.EFBIG },
        { PosixErrorCode.ENOSPC.ErrorCode, PosixErrorCode.ENOSPC },
        { PosixErrorCode.ESPIPE.ErrorCode, PosixErrorCode.ESPIPE },
        { PosixErrorCode.EROFS.ErrorCode, PosixErrorCode.EROFS },
        { PosixErrorCode.EMLINK.ErrorCode, PosixErrorCode.EMLINK },
        { PosixErrorCode.EPIPE.ErrorCode, PosixErrorCode.EPIPE },
        { PosixErrorCode.EDOM.ErrorCode, PosixErrorCode.EDOM },
        { PosixErrorCode.ERANGE.ErrorCode, PosixErrorCode.ERANGE },
        { PosixErrorCode.EWOULDBLOCK.ErrorCode, PosixErrorCode.EWOULDBLOCK },
        { PosixErrorCode.EDEADLK.ErrorCode, PosixErrorCode.EDEADLK },
        { PosixErrorCode.ENAMETOOLONG.ErrorCode, PosixErrorCode.ENAMETOOLONG },
        { PosixErrorCode.ENOLCK.ErrorCode, PosixErrorCode.ENOLCK },
        { PosixErrorCode.ENOSYS.ErrorCode, PosixErrorCode.ENOSYS },
        { PosixErrorCode.ENOTEMPTY.ErrorCode, PosixErrorCode.ENOTEMPTY },
        { PosixErrorCode.ELOOP.ErrorCode, PosixErrorCode.ELOOP },
        { PosixErrorCode.ENOMSG.ErrorCode, PosixErrorCode.ENOMSG },
        { PosixErrorCode.EIDRM.ErrorCode, PosixErrorCode.EIDRM },
        { PosixErrorCode.ECHRNG.ErrorCode, PosixErrorCode.ECHRNG },
        { PosixErrorCode.EL2NSYNC.ErrorCode, PosixErrorCode.EL2NSYNC },
        { PosixErrorCode.EL3HLT.ErrorCode, PosixErrorCode.EL3HLT },
        { PosixErrorCode.EL3RST.ErrorCode, PosixErrorCode.EL3RST },
        { PosixErrorCode.ELNRNG.ErrorCode, PosixErrorCode.ELNRNG },
        { PosixErrorCode.EUNATCH.ErrorCode, PosixErrorCode.EUNATCH },
        { PosixErrorCode.ENOCSI.ErrorCode, PosixErrorCode.ENOCSI },
        { PosixErrorCode.EL2HLT.ErrorCode, PosixErrorCode.EL2HLT },
        { PosixErrorCode.EBADE.ErrorCode, PosixErrorCode.EBADE },
        { PosixErrorCode.EBADR.ErrorCode, PosixErrorCode.EBADR },
        { PosixErrorCode.EXFULL.ErrorCode, PosixErrorCode.EXFULL },
        { PosixErrorCode.ENOANO.ErrorCode, PosixErrorCode.ENOANO },
        { PosixErrorCode.EBADRQC.ErrorCode, PosixErrorCode.EBADRQC },
        { PosixErrorCode.EBADSLT.ErrorCode, PosixErrorCode.EBADSLT },
        { PosixErrorCode.EDEADLOCK.ErrorCode, PosixErrorCode.EDEADLOCK },
        { PosixErrorCode.EBFONT.ErrorCode, PosixErrorCode.EBFONT },
        { PosixErrorCode.ENOSTR.ErrorCode, PosixErrorCode.ENOSTR },
        { PosixErrorCode.ENODATA.ErrorCode, PosixErrorCode.ENODATA },
        { PosixErrorCode.ETIME.ErrorCode, PosixErrorCode.ETIME },
        { PosixErrorCode.ENOSR.ErrorCode, PosixErrorCode.ENOSR },
        { PosixErrorCode.ENONET.ErrorCode, PosixErrorCode.ENONET },
        { PosixErrorCode.ENOPKG.ErrorCode, PosixErrorCode.ENOPKG },
        { PosixErrorCode.EREMOTE.ErrorCode, PosixErrorCode.EREMOTE },
        { PosixErrorCode.ENOLINK.ErrorCode, PosixErrorCode.ENOLINK },
        { PosixErrorCode.EADV.ErrorCode, PosixErrorCode.EADV },
        { PosixErrorCode.ESRMNT.ErrorCode, PosixErrorCode.ESRMNT },
        { PosixErrorCode.ECOMM.ErrorCode, PosixErrorCode.ECOMM },
        { PosixErrorCode.EPROTO.ErrorCode, PosixErrorCode.EPROTO },
        { PosixErrorCode.EMULTIHOP.ErrorCode, PosixErrorCode.EMULTIHOP },
        { PosixErrorCode.EDOTDOT.ErrorCode, PosixErrorCode.EDOTDOT },
        { PosixErrorCode.EBADMSG.ErrorCode, PosixErrorCode.EBADMSG },
        { PosixErrorCode.EOVERFLOW.ErrorCode, PosixErrorCode.EOVERFLOW },
        { PosixErrorCode.ENOTUNIQ.ErrorCode, PosixErrorCode.ENOTUNIQ },
        { PosixErrorCode.EBADFD.ErrorCode, PosixErrorCode.EBADFD },
        { PosixErrorCode.EREMCHG.ErrorCode, PosixErrorCode.EREMCHG },
        { PosixErrorCode.ELIBACC.ErrorCode, PosixErrorCode.ELIBACC },
        { PosixErrorCode.ELIBBAD.ErrorCode, PosixErrorCode.ELIBBAD },
        { PosixErrorCode.ELIBSCN.ErrorCode, PosixErrorCode.ELIBSCN },
        { PosixErrorCode.ELIBMAX.ErrorCode, PosixErrorCode.ELIBMAX },
        { PosixErrorCode.ELIBEXEC.ErrorCode, PosixErrorCode.ELIBEXEC },
        { PosixErrorCode.EILSEQ.ErrorCode, PosixErrorCode.EILSEQ },
        { PosixErrorCode.ERESTART.ErrorCode, PosixErrorCode.ERESTART },
        { PosixErrorCode.ESTRPIPE.ErrorCode, PosixErrorCode.ESTRPIPE },
        { PosixErrorCode.EUSERS.ErrorCode, PosixErrorCode.EUSERS },
        { PosixErrorCode.ENOTSOCK.ErrorCode, PosixErrorCode.ENOTSOCK },
        { PosixErrorCode.EDESTADDRREQ.ErrorCode, PosixErrorCode.EDESTADDRREQ },
        { PosixErrorCode.EMSGSIZE.ErrorCode, PosixErrorCode.EMSGSIZE },
        { PosixErrorCode.EPROTOTYPE.ErrorCode, PosixErrorCode.EPROTOTYPE },
        { PosixErrorCode.ENOPROTOOPT.ErrorCode, PosixErrorCode.ENOPROTOOPT },
        { PosixErrorCode.EPROTONOSUPPORT.ErrorCode, PosixErrorCode.EPROTONOSUPPORT },
        { PosixErrorCode.ESOCKTNOSUPPORT.ErrorCode, PosixErrorCode.ESOCKTNOSUPPORT },
        { PosixErrorCode.EOPNOTSUPP.ErrorCode, PosixErrorCode.EOPNOTSUPP },
        { PosixErrorCode.EPFNOSUPPORT.ErrorCode, PosixErrorCode.EPFNOSUPPORT },
        { PosixErrorCode.EAFNOSUPPORT.ErrorCode, PosixErrorCode.EAFNOSUPPORT },
        { PosixErrorCode.EADDRINUSE.ErrorCode, PosixErrorCode.EADDRINUSE },
        { PosixErrorCode.EADDRNOTAVAIL.ErrorCode, PosixErrorCode.EADDRNOTAVAIL },
        { PosixErrorCode.ENETDOWN.ErrorCode, PosixErrorCode.ENETDOWN },
        { PosixErrorCode.ENETUNREACH.ErrorCode, PosixErrorCode.ENETUNREACH },
        { PosixErrorCode.ENETRESET.ErrorCode, PosixErrorCode.ENETRESET },
        { PosixErrorCode.ECONNABORTED.ErrorCode, PosixErrorCode.ECONNABORTED },
        { PosixErrorCode.ECONNRESET.ErrorCode, PosixErrorCode.ECONNRESET },
        { PosixErrorCode.ENOBUFS.ErrorCode, PosixErrorCode.ENOBUFS },
        { PosixErrorCode.EISCONN.ErrorCode, PosixErrorCode.EISCONN },
        { PosixErrorCode.ENOTCONN.ErrorCode, PosixErrorCode.ENOTCONN },
        { PosixErrorCode.ESHUTDOWN.ErrorCode, PosixErrorCode.ESHUTDOWN },
        { PosixErrorCode.ETOOMANYREFS.ErrorCode, PosixErrorCode.ETOOMANYREFS },
        { PosixErrorCode.ETIMEDOUT.ErrorCode, PosixErrorCode.ETIMEDOUT },
        { PosixErrorCode.ECONNREFUSED.ErrorCode, PosixErrorCode.ECONNREFUSED },
        { PosixErrorCode.EHOSTDOWN.ErrorCode, PosixErrorCode.EHOSTDOWN },
        { PosixErrorCode.EHOSTUNREACH.ErrorCode, PosixErrorCode.EHOSTUNREACH },
        { PosixErrorCode.EALREADY.ErrorCode, PosixErrorCode.EALREADY },
        { PosixErrorCode.EINPROGRESS.ErrorCode, PosixErrorCode.EINPROGRESS },
        { PosixErrorCode.ESTALE.ErrorCode, PosixErrorCode.ESTALE },
        { PosixErrorCode.EUCLEAN.ErrorCode, PosixErrorCode.EUCLEAN },
        { PosixErrorCode.ENOTNAM.ErrorCode, PosixErrorCode.ENOTNAM },
        { PosixErrorCode.ENAVAIL.ErrorCode, PosixErrorCode.ENAVAIL },
        { PosixErrorCode.EISNAM.ErrorCode, PosixErrorCode.EISNAM },
        { PosixErrorCode.EREMOTEIO.ErrorCode, PosixErrorCode.EREMOTEIO },
        { PosixErrorCode.EDQUOT.ErrorCode, PosixErrorCode.EDQUOT },
        { PosixErrorCode.ENOMEDIUM.ErrorCode, PosixErrorCode.ENOMEDIUM },
        { PosixErrorCode.EMEDIUMTYPE.ErrorCode, PosixErrorCode.EMEDIUMTYPE },
        { PosixErrorCode.ECANCELED.ErrorCode, PosixErrorCode.ECANCELED },
        { PosixErrorCode.ENOKEY.ErrorCode, PosixErrorCode.ENOKEY },
        { PosixErrorCode.EKEYEXPIRED.ErrorCode, PosixErrorCode.EKEYEXPIRED },
        { PosixErrorCode.EKEYREVOKED.ErrorCode, PosixErrorCode.EKEYREVOKED },
        { PosixErrorCode.EKEYREJECTED.ErrorCode, PosixErrorCode.EKEYREJECTED },
        { PosixErrorCode.EOWNERDEAD.ErrorCode, PosixErrorCode.EOWNERDEAD },
        { PosixErrorCode.ENOTRECOVERABLE.ErrorCode, PosixErrorCode.ENOTRECOVERABLE },
        { PosixErrorCode.ERFKILL.ErrorCode, PosixErrorCode.ERFKILL },
        { PosixErrorCode.EHWPOISON.ErrorCode, PosixErrorCode.EHWPOISON },
    };
}

public readonly struct PosixErrorCode
{
    public readonly string Errno;
    public readonly int ErrorCode;
    public readonly string ErrorMessage;

    public PosixErrorCode(string errno, int errorCode, string errorMessage)
    {
        Errno = errno;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
    }

    public override string ToString() => $"{ErrorCode} ({Errno}): {ErrorMessage}";

    public static PosixErrorCode EPERM { get; } = new("EPERM", 1, "Operation not permitted");
    public static PosixErrorCode ENOENT { get; } = new("ENOENT", 2, "No such file or directory");
    public static PosixErrorCode ESRCH { get; } = new("ESRCH", 3, "No such process");
    public static PosixErrorCode EINTR { get; } = new("EINTR", 4, "Interrupted system call");
    public static PosixErrorCode EIO { get; } = new("EIO", 5, "I/O error");
    public static PosixErrorCode ENXIO { get; } = new("ENXIO", 6, "No such device or address");
    public static PosixErrorCode E2BIG { get; } = new("E2BIG", 7, "Argument list too long");
    public static PosixErrorCode ENOEXEC { get; } = new("ENOEXEC", 8, "Exec format error");
    public static PosixErrorCode EBADF { get; } = new("EBADF", 9, "Bad file number");
    public static PosixErrorCode ECHILD { get; } = new("ECHILD", 10, "No child processes");
    public static PosixErrorCode EAGAIN { get; } = new("EAGAIN", 11, "Try again");
    public static PosixErrorCode ENOMEM { get; } = new("ENOMEM", 12, "Out of memory");
    public static PosixErrorCode EACCES { get; } = new("EACCES", 13, "Permission denied");
    public static PosixErrorCode EFAULT { get; } = new("EFAULT", 14, "Bad address");
    public static PosixErrorCode ENOTBLK { get; } = new("ENOTBLK", 15, "Block device required");
    public static PosixErrorCode EBUSY { get; } = new("EBUSY", 16, "Device or resource busy");
    public static PosixErrorCode EEXIST { get; } = new("EEXIST", 17, "File exists");
    public static PosixErrorCode EXDEV { get; } = new("EXDEV", 18, "Cross-device link");
    public static PosixErrorCode ENODEV { get; } = new("ENODEV", 19, "No such device");
    public static PosixErrorCode ENOTDIR { get; } = new("ENOTDIR", 20, "Not a directory");
    public static PosixErrorCode EISDIR { get; } = new("EISDIR", 21, "Is a directory");
    public static PosixErrorCode EINVAL { get; } = new("EINVAL", 22, "Invalid argument");
    public static PosixErrorCode ENFILE { get; } = new("ENFILE", 23, "File table overflow");
    public static PosixErrorCode EMFILE { get; } = new("EMFILE", 24, "Too many open files");
    public static PosixErrorCode ENOTTY { get; } = new("ENOTTY", 25, "Not a typewriter");
    public static PosixErrorCode ETXTBSY { get; } = new("ETXTBSY", 26, "Text file busy");
    public static PosixErrorCode EFBIG { get; } = new("EFBIG", 27, "File too large");
    public static PosixErrorCode ENOSPC { get; } = new("ENOSPC", 28, "No space left on device");
    public static PosixErrorCode ESPIPE { get; } = new("ESPIPE", 29, "Illegal seek");
    public static PosixErrorCode EROFS { get; } = new("EROFS", 30, "Read-only file system");
    public static PosixErrorCode EMLINK { get; } = new("EMLINK", 31, "Too many links");
    public static PosixErrorCode EPIPE { get; } = new("EPIPE", 32, "Broken pipe");
    public static PosixErrorCode EDOM { get; } = new("EDOM", 33, "Math argument out of domain of func");
    public static PosixErrorCode ERANGE { get; } = new("ERANGE", 34, "Math result not representable");
    public static PosixErrorCode EWOULDBLOCK { get; } = new("EWOULDBLOCK", 11, "Operation would block");
    public static PosixErrorCode EDEADLK { get; } = new("EDEADLK", 35, "Resource deadlock would occur");
    public static PosixErrorCode ENAMETOOLONG { get; } = new("ENAMETOOLONG", 36, "File name too long");
    public static PosixErrorCode ENOLCK { get; } = new("ENOLCK", 37, "No record locks available");
    public static PosixErrorCode ENOSYS { get; } = new("ENOSYS", 38, "Invalid system call number");
    public static PosixErrorCode ENOTEMPTY { get; } = new("ENOTEMPTY", 39, "Directory not empty");
    public static PosixErrorCode ELOOP { get; } = new("ELOOP", 40, "Too many symbolic links encountered");
    public static PosixErrorCode ENOMSG { get; } = new("ENOMSG", 42, "No message of desired type");
    public static PosixErrorCode EIDRM { get; } = new("EIDRM", 43, "Identifier removed");
    public static PosixErrorCode ECHRNG { get; } = new("ECHRNG", 44, "Channel number out of range");
    public static PosixErrorCode EL2NSYNC { get; } = new("EL2NSYNC", 45, "Level 2 not synchronized");
    public static PosixErrorCode EL3HLT { get; } = new("EL3HLT", 46, "Level 3 halted");
    public static PosixErrorCode EL3RST { get; } = new("EL3RST", 47, "Level 3 reset");
    public static PosixErrorCode ELNRNG { get; } = new("ELNRNG", 48, "Link number out of range");
    public static PosixErrorCode EUNATCH { get; } = new("EUNATCH", 49, "Protocol driver not attached");
    public static PosixErrorCode ENOCSI { get; } = new("ENOCSI", 50, "No CSI structure available");
    public static PosixErrorCode EL2HLT { get; } = new("EL2HLT", 51, "Level 2 halted");
    public static PosixErrorCode EBADE { get; } = new("EBADE", 52, "Invalid exchange");
    public static PosixErrorCode EBADR { get; } = new("EBADR", 53, "Invalid request descriptor");
    public static PosixErrorCode EXFULL { get; } = new("EXFULL", 54, "Exchange full");
    public static PosixErrorCode ENOANO { get; } = new("ENOANO", 55, "No anode");
    public static PosixErrorCode EBADRQC { get; } = new("EBADRQC", 56, "Invalid request code");
    public static PosixErrorCode EBADSLT { get; } = new("EBADSLT", 57, "Invalid slot");
    public static PosixErrorCode EDEADLOCK { get; } = new("EDEADLOCK", 35, "Resource deadlock would occur");
    public static PosixErrorCode EBFONT { get; } = new("EBFONT", 59, "Bad font file format");
    public static PosixErrorCode ENOSTR { get; } = new("ENOSTR", 60, "Device not a stream");
    public static PosixErrorCode ENODATA { get; } = new("ENODATA", 61, "No data available");
    public static PosixErrorCode ETIME { get; } = new("ETIME", 62, "Timer expired");
    public static PosixErrorCode ENOSR { get; } = new("ENOSR", 63, "Out of streams resources");
    public static PosixErrorCode ENONET { get; } = new("ENONET", 64, "Machine is not on the network");
    public static PosixErrorCode ENOPKG { get; } = new("ENOPKG", 65, "Package not installed");
    public static PosixErrorCode EREMOTE { get; } = new("EREMOTE", 66, "Object is remote");
    public static PosixErrorCode ENOLINK { get; } = new("ENOLINK", 67, "Link has been severed");
    public static PosixErrorCode EADV { get; } = new("EADV", 68, "Advertise error");
    public static PosixErrorCode ESRMNT { get; } = new("ESRMNT", 69, "Srmount error");
    public static PosixErrorCode ECOMM { get; } = new("ECOMM", 70, "Communication error on send");
    public static PosixErrorCode EPROTO { get; } = new("EPROTO", 71, "Protocol error");
    public static PosixErrorCode EMULTIHOP { get; } = new("EMULTIHOP", 72, "Multihop attempted");
    public static PosixErrorCode EDOTDOT { get; } = new("EDOTDOT", 73, "RFS specific error");
    public static PosixErrorCode EBADMSG { get; } = new("EBADMSG", 74, "Not a data message");
    public static PosixErrorCode EOVERFLOW { get; } = new("EOVERFLOW", 75, "Value too large for defined data type");
    public static PosixErrorCode ENOTUNIQ { get; } = new("ENOTUNIQ", 76, "Name not unique on network");
    public static PosixErrorCode EBADFD { get; } = new("EBADFD", 77, "File descriptor in bad state");
    public static PosixErrorCode EREMCHG { get; } = new("EREMCHG", 78, "Remote address changed");
    public static PosixErrorCode ELIBACC { get; } = new("ELIBACC", 79, "Can not access a needed shared library");
    public static PosixErrorCode ELIBBAD { get; } = new("ELIBBAD", 80, "Accessing a corrupted shared library");
    public static PosixErrorCode ELIBSCN { get; } = new("ELIBSCN", 81, ".lib section in a.out corrupted");
    public static PosixErrorCode ELIBMAX { get; } = new("ELIBMAX", 82, "Attempting to link in too many shared libraries");
    public static PosixErrorCode ELIBEXEC { get; } = new("ELIBEXEC", 83, "Cannot exec a shared library directly");
    public static PosixErrorCode EILSEQ { get; } = new("EILSEQ", 84, "Illegal byte sequence");
    public static PosixErrorCode ERESTART { get; } = new("ERESTART", 85, "Interrupted system call should be restarted");
    public static PosixErrorCode ESTRPIPE { get; } = new("ESTRPIPE", 86, "Streams pipe error");
    public static PosixErrorCode EUSERS { get; } = new("EUSERS", 87, "Too many users");
    public static PosixErrorCode ENOTSOCK { get; } = new("ENOTSOCK", 88, "Socket operation on non-socket");
    public static PosixErrorCode EDESTADDRREQ { get; } = new("EDESTADDRREQ", 89, "Destination address required");
    public static PosixErrorCode EMSGSIZE { get; } = new("EMSGSIZE", 90, "Message too long");
    public static PosixErrorCode EPROTOTYPE { get; } = new("EPROTOTYPE", 91, "Protocol wrong type for socket");
    public static PosixErrorCode ENOPROTOOPT { get; } = new("ENOPROTOOPT", 92, "Protocol not available");
    public static PosixErrorCode EPROTONOSUPPORT { get; } = new("EPROTONOSUPPORT", 93, "Protocol not supported");
    public static PosixErrorCode ESOCKTNOSUPPORT { get; } = new("ESOCKTNOSUPPORT", 94, "Socket type not supported");
    public static PosixErrorCode EOPNOTSUPP { get; } = new("EOPNOTSUPP", 95, "Operation not supported on transport endpoint");
    public static PosixErrorCode EPFNOSUPPORT { get; } = new("EPFNOSUPPORT", 96, "Protocol family not supported");
    public static PosixErrorCode EAFNOSUPPORT { get; } = new("EAFNOSUPPORT", 97, "Address family not supported by protocol");
    public static PosixErrorCode EADDRINUSE { get; } = new("EADDRINUSE", 98, "Address already in use");
    public static PosixErrorCode EADDRNOTAVAIL { get; } = new("EADDRNOTAVAIL", 99, "Cannot assign requested address");
    public static PosixErrorCode ENETDOWN { get; } = new("ENETDOWN", 100, "Network is down");
    public static PosixErrorCode ENETUNREACH { get; } = new("ENETUNREACH", 101, "Network is unreachable");
    public static PosixErrorCode ENETRESET { get; } = new("ENETRESET", 102, "Network dropped connection because of reset");
    public static PosixErrorCode ECONNABORTED { get; } = new("ECONNABORTED", 103, "Software caused connection abort");
    public static PosixErrorCode ECONNRESET { get; } = new("ECONNRESET", 104, "Connection reset by peer");
    public static PosixErrorCode ENOBUFS { get; } = new("ENOBUFS", 105, "No buffer space available");
    public static PosixErrorCode EISCONN { get; } = new("EISCONN", 106, "Transport endpoint is already connected");
    public static PosixErrorCode ENOTCONN { get; } = new("ENOTCONN", 107, "Transport endpoint is not connected");
    public static PosixErrorCode ESHUTDOWN { get; } = new("ESHUTDOWN", 108, "Cannot send after transport endpoint shutdown");
    public static PosixErrorCode ETOOMANYREFS { get; } = new("ETOOMANYREFS", 109, "Too many references: cannot splice");
    public static PosixErrorCode ETIMEDOUT { get; } = new("ETIMEDOUT", 110, "Connection timed out");
    public static PosixErrorCode ECONNREFUSED { get; } = new("ECONNREFUSED", 111, "Connection refused");
    public static PosixErrorCode EHOSTDOWN { get; } = new("EHOSTDOWN", 112, "Host is down");
    public static PosixErrorCode EHOSTUNREACH { get; } = new("EHOSTUNREACH", 113, "No route to host");
    public static PosixErrorCode EALREADY { get; } = new("EALREADY", 114, "Operation already in progress");
    public static PosixErrorCode EINPROGRESS { get; } = new("EINPROGRESS", 115, "Operation now in progress");
    public static PosixErrorCode ESTALE { get; } = new("ESTALE", 116, "Stale file handle");
    public static PosixErrorCode EUCLEAN { get; } = new("EUCLEAN", 117, "Structure needs cleaning");
    public static PosixErrorCode ENOTNAM { get; } = new("ENOTNAM", 118, "Not a XENIX named type file");
    public static PosixErrorCode ENAVAIL { get; } = new("ENAVAIL", 119, "No XENIX semaphores available");
    public static PosixErrorCode EISNAM { get; } = new("EISNAM", 120, "Is a named type file");
    public static PosixErrorCode EREMOTEIO { get; } = new("EREMOTEIO", 121, "Remote I/O error");
    public static PosixErrorCode EDQUOT { get; } = new("EDQUOT", 122, "Quota exceeded");
    public static PosixErrorCode ENOMEDIUM { get; } = new("ENOMEDIUM", 123, "No medium found");
    public static PosixErrorCode EMEDIUMTYPE { get; } = new("EMEDIUMTYPE", 124, "Wrong medium type");
    public static PosixErrorCode ECANCELED { get; } = new("ECANCELED", 125, "Operation Canceled");
    public static PosixErrorCode ENOKEY { get; } = new("ENOKEY", 126, "Required key not available");
    public static PosixErrorCode EKEYEXPIRED { get; } = new("EKEYEXPIRED", 127, "Key has expired");
    public static PosixErrorCode EKEYREVOKED { get; } = new("EKEYREVOKED", 128, "Key has been revoked");
    public static PosixErrorCode EKEYREJECTED { get; } = new("EKEYREJECTED", 129, "Key was rejected by service");
    public static PosixErrorCode EOWNERDEAD { get; } = new("EOWNERDEAD", 130, "Owner died");
    public static PosixErrorCode ENOTRECOVERABLE { get; } = new("ENOTRECOVERABLE", 131, "State not recoverable");
    public static PosixErrorCode ERFKILL { get; } = new("ERFKILL", 132, "Operation not possible due to RF-kill");
    public static PosixErrorCode EHWPOISON { get; } = new("EHWPOISON", 133, "Memory page has hardware error");
    public static PosixErrorCode UnknownError { get; } = new("Unknown error", -1, "Unknown error");
}