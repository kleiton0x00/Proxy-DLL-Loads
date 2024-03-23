// Proxying DLL Loads using undocumented syscalls (TpAllocWait, TpSetWait & TpWaitForWait)
// ~ Resources ~
// Process Hacker:        https://processhacker.sourceforge.io/doc/nttp_8h.html
// DarkVortex's Blogpost: https://github.com/paranoidninja/Proxy-DLL-Loads/blob/main/proxyDllLoads.c
// MSDN:                  https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions
// Author:                @kleiton0x7e

#include <windows.h>
#include <stdio.h>

#define ALLOC_ON_CODE _Pragma("section(\".text\")") __declspec(allocate(".text"))

ALLOC_ON_CODE unsigned char CallbackStub[] = {

    0x48, 0x89, 0xd3,            // mov rbx, rdx
    0x48, 0x8b, 0x03,            // mov rax, QWORD PTR[rbx]        ; rax - pointer to LoadLibraryA function
    0x48, 0x8b, 0x4b, 0x08,      // mov rcx, QWORD PTR[rbx + 0x8]  ; rcx - first argument (library name)
    0xff, 0xe0                   // jmp rax                        ; instead of pushing the return address, we jump instead (clean stack)

};

typedef ULONG LOGICAL;

typedef struct _LOADLIBRARY_ARGS {
    UINT_PTR pLoadLibraryA;
    LPCSTR lpLibFileName;
} LOADLIBRARY_ARGS, * PLOADLIBRARY_ARGS;

typedef NTSTATUS(NTAPI* TPALLOCWAIT)(_Out_ PTP_WAIT* WaitReturn,
    _In_ PTP_WAIT_CALLBACK  	    Callback,
    _Inout_opt_ PVOID  	            Context,
    _In_opt_ PTP_CALLBACK_ENVIRON  	CallbackEnviron
    );

typedef NTSTATUS(NTAPI* TPSETWAIT) 	(_Inout_ PTP_WAIT  	Wait,
    _In_opt_ HANDLE  	            Handle,
    _In_opt_ PLARGE_INTEGER  	    Timeout
    );

typedef NTSTATUS(NTAPI* TPWAITFORWAIT) (_Inout_ PTP_WAIT  	Wait,
    _In_ LOGICAL  	                CancelPendingCallbacks
    );

HMODULE proxiedLoadLibraryA(LPCSTR libName) {

    PTP_WAIT WaitReturn = NULL;
    HANDLE hEvent       = NULL;
    UINT i              = 0;
    
    LOADLIBRARY_ARGS loadLibraryArgs = { 0 };
    loadLibraryArgs.pLoadLibraryA = (UINT_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    loadLibraryArgs.lpLibFileName = libName;

    FARPROC pTpAllocWait = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocWait");
    FARPROC pTpSetWait = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpSetWait");
    FARPROC pTpWaitForWait = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpWaitForWait");
    
    // Create an auto-reset event.
    hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (NULL == hEvent) {
        // Error Handling
        return 0;
    }

    ((TPALLOCWAIT)pTpAllocWait)(&WaitReturn, (PTP_WAIT_CALLBACK)(unsigned char*)CallbackStub, &loadLibraryArgs, 0);

    // Need to re-register the event with the wait object
    // each time before signaling the event to trigger the wait callback.
    for (i = 0; i < 5; i++) {
        ((TPSETWAIT)pTpSetWait)(WaitReturn, hEvent, NULL);
        SetEvent(hEvent);
        Sleep(500);                                             // Delay for the waiter thread to act if necessary.
        ((TPWAITFORWAIT)pTpWaitForWait)(WaitReturn, FALSE);     // Block here until the callback function is done executing.
    }

    return GetModuleHandleA(libName);                           // Return the address of the loaded library

}

int main() {
    HMODULE user32 = proxiedLoadLibraryA("user32.dll");
    printf("user32.dll Address: %p\n", user32);
}
