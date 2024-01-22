# Proxy DLL Loads
A repository with different scripts to demonstrate the DLL-load proxying using undocumented Syscalls or VEH. This repo is not about teaching you what DLL Load proxying is and how it works, it is greatly explained on [this blogpost](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/). Instead, the main focus is on explaining how the DLL be loaded using VEH and on finding undocumented callback functions by reversing the DLLs and creating your own version. Below are the two methods used to proxy DLL Load:  

## 1. VEH  

We'll leverage the **VEH (Vectored Exception Handler)** to modify the context, especially RIP register to take us to the LoadLibraryA, and the RCX to hold the function's argument (module name) of `LoadLibraryA`. To trigger our exception, VirtualProtect is used to set the page to `PAGE_GUARD`, thus triggering the `STATUS_GUARD_PAGE_VIOLATION`.

## 2. Tp* Syscalls

### Hunting for undocumented syscalls

Before getting in directly to reversing the DLLs, we need to first know what to look for. We can start by looking at the Microsoft documentation (MSDN), which provides an excellent [example](https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions?source=recommendations) of a custom thread pool, which creates a work item and a thread pool timer. The code alone is also suitable for archiving the execution of `LoadLibrary` via callback functions, but as already known, the userland functions are prone to hooking. So using their respective syscalls would be a better approach. Looking at the MSDN documentation, the example code uses the following Win32API functions:  

```
CreateThreadpool
SetThreadpoolThreadMaximum
SetThreadpoolThreadMinimum
CreateThreadpoolCleanupGroup
CreateThreadpoolTimer
SetThreadpoolTimer
CloseThreadpoolCleanupGroupMembers
```

If you use [IDA](https://hex-rays.com/ida-free/), open kernel32.dll, go to "Exports" and search for the mentioned Win32 APIs, in this case `CreateThreadpool`. Double-clicking the function redirect us to its dissassembled code:  
![Screenshot from 2023-10-23 10-33-17](https://github.com/kleiton0x00/Proxy-DLL-Loads/assets/37262788/8422c046-13df-45fd-8c48-1371f52e9f43)  
Through the assembly instructions, we see the `TpAllocPool` syscall being executed: `call    cs:__imp_TpAllocPool`

If you repeat the process with the other functions, you will end up with the following syscalls:   
```
Ntdll!TpAllocPool
Ntdll!TpSetPoolMaxThreads
Ntdll!TpSetPoolMinThreads
Ntdll!TpAllocCleanupGroup
Ntdll!TpAllocTimer
Ntdll!TpSetTimer
Ntdll!TpReleaseCleanupGroupMembers
```

Now you have everything you need to start creating your own version of proxying the DLL Loads. You can look at [this documentation](https://processhacker.sourceforge.io/doc/nttp_8h.html#adad18de6710381f08cf36a0fa72e7529) from Process Hacker to help you implement the undocumented syscalls in your code.  

### Debugging

Set a breakpoint before the assembly code in Callbackstub get's executed. Look at right tab of [x64dbg](https://x64dbg.com/) as the registers are being populated.  

https://github.com/kleiton0x00/Proxy-DLL-Loads/assets/37262788/73af5145-2b1c-486b-ae9f-583c4e865df6

```
RAX -> pointer to LoadLibraryA
RCX -> library name string 
```

### Result  
![Screenshot from 2023-10-21 20-21-05](https://github.com/kleiton0x00/Proxy-DLL-Loads/assets/37262788/2db0e36d-53e9-4697-b976-b1260f5bfcdd)

## Resources  
https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/  
https://github.com/hlldz/misc/tree/main/proxy_calls  
https://processhacker.sourceforge.io/doc/nttp_8h.html#adad18de6710381f08cf36a0fa72e7529  

## Detections

https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/defense_evasion_library_loaded_via_a_callback_function.toml  
