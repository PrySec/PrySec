# PrySec - Privacy & Security framework for your .NET applications

Stop people from prying around in your process's memory!

---

## Planned key features

### Defensive

- Cross platform memory protection providing low and high level access to protected memory using [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API) on Windows NT and custom AES256-CBC-HMAC-BLAKE2b memory protection on UNIX systems keeping your passwords and sensitive data safe safe from memory dumps and snooping.
- Managed and unmanaged debugger detection and mitigation, thread hiding, etc ...
- Resource protection - protect your application resources in compressed and encrypted key-value binary blobs.
  
### Security

- High performance cryptography library (AES, SHA family hashes, Scrypt, BLAKE2, ...) operating completely on protected memory, allowing you to use your protected secrets without compromising them (unlike [`SecureString`](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-5.0) for example).
- Unified high and low level interfaces for all cryptographic functions  for protected and unprotected memory.

### Offensive

- Low and high level interfaces for process interop, dll injection, process hollowing and X86 assembly generation.

### And much more...

- Unmanaged memory framework and allocation tracking - prevent memory leaks in your unmanaged code.
- Bit manipulation utilities - easily swap endianness
- WinAPI data types - Easy .NET to Windows type conversion. Do you miss your `DWORD`s, `BSTR`s and `LPCTSTR`s? Me neither, but if you have to use them for interop - here you go.
