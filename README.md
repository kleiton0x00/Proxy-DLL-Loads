# Proxy DLL Loads
A proof of concept demonstrating the DLL-load proxying using undocumented Syscalls. This repo is not about teaching you what DLL Load proxying is and how it works, it is greatly explained on [this blogpost](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/). Instead, the main focus is on finding undocumented callback functions by reversing the DLLs and creating your own version. 

## Hunting for undocumented syscalls

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
![image](https://github.com/kleiton0x00/Proxy-DLL-Loads/assets/37262788/736ec85c-1086-405a-89c7-e9bdec40443c)  
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

Now you have everything you need to start creating your own version of proxying the DLL Loads.

## Resources  
https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/  
https://github.com/hlldz/misc/tree/main/proxy_calls  

## Detections

https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/defense_evasion_library_loaded_via_a_callback_function.toml  
