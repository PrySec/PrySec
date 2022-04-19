# PrySec - Privacy & Security framework for your .NET applications

Stop people from prying around in your process's memory!

![dotnet-core-windows](https://github.com/frederik-hoeft/PrySec/actions/workflows/windows.yml/badge.svg)
![dotnet-core-ubuntu](https://github.com/frederik-hoeft/PrySec/actions/workflows/ubuntu.yml/badge.svg)
![dotnet-core-macos](https://github.com/frederik-hoeft/PrySec/actions/workflows/macos.yml/badge.svg)
[![CodeFactor](https://www.codefactor.io/repository/github/frederik-hoeft/prysec/badge?s=adaf32ed48d673d2c1f5aa80e15614d2f0b16278)](https://www.codefactor.io/repository/github/frederik-hoeft/prysec)

---

## Planned key features

### Defensive

- [ ] Cross platform memory protection providing low and high level access to protected memory using [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API) on Windows NT and custom AES256-CBC-HMAC-BLAKE2b memory protection on UNIX systems keeping your passwords and sensitive data safe from memory dumps and snooping.
- [ ] Simple managed and unmanaged debugger detection and mitigation, thread hiding, etc ...
- [ ] Resource protection - protect your application resources in compressed and encrypted key-value binary blobs.
  
### Security

- High performance cryptography library (AES, SHA family hashes, Scrypt, BLAKE2, ...) operating completely on protected memory, allowing you to use your protected secrets without compromising them (unlike [`SecureString`](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-5.0) for example).
  - [ ] SHA Family
    - [x] SHA-1
    - [x] SHA-224
    - [x] SHA-256
    - [x] SHA-384
    - [x] SHA-512
    - [ ] SHA-3
  - [x] BLAKE2
  - [x] BLAKE3
  - [ ] AES-256
  - [ ] Scrypt
- Unified high and low level interfaces for all cryptographic functions  for protected and unprotected memory alike.

### Offensive

- [ ] Low and high level interfaces for process interop, dll injection, process hollowing and X86 assembly generation.

### And much more...

- [x] Unmanaged memory framework and allocation tracking - prevent memory leaks in your unmanaged code.
- [ ] Bit manipulation utilities - easily swap endianness.
- [ ] WinAPI data types - Easy .NET to Windows type conversion. Do you miss your `DWORD`s, `BSTR`s and `LPCTSTR`s? Me neither, but if you have to use them for interop - here you go.
