#include "CFG.h"

#define ALLOC_ON_CODE _Pragma("section(\".text\")") __declspec(allocate(".text"))

ALLOC_ON_CODE unsigned char CallbackStub[] = {

    0x48, 0x89, 0xd3,            // mov rbx, rdx
    0x48, 0x8b, 0x03,            // mov rax, QWORD PTR[rbx]        ; rax - pointer to LoadLibraryA function
    0x48, 0x8b, 0x4b, 0x08,      // mov rcx, QWORD PTR[rbx + 0x8]  ; rcx - first argument (library name)
    0xff, 0xe0                   // jmp rax                        ; instead of pushing the return address, we jump instead (clean stack)

};

typedef struct _LOADLIBRARY_ARGS {
    UINT_PTR pLoadLibraryA;
    LPCSTR lpLibFileName;
} LOADLIBRARY_ARGS, * PLOADLIBRARY_ARGS;

typedef NTSTATUS(NTAPI* TPALLOCPOOL)(_Out_ PTP_POOL* PoolReturn,
    _Reserved_ PVOID  	Reserved
    );

typedef NTSTATUS(NTAPI* TPSETPOOLMAXTHREADS)(_Inout_ PTP_POOL  	Pool,
    _In_ LONG  	MaxThreads
    );

typedef NTSTATUS(NTAPI* TPSETPOOLMINTHREADS)(_Inout_ PTP_POOL  	Pool,
    _In_ LONG  	MinThreads
    );

typedef NTSTATUS(NTAPI* TPALLOCCLEANUPGROUP)(_Out_ PTP_CLEANUP_GROUP* CleanupGroupReturn);

typedef NTSTATUS(NTAPI* TPALLOCTIMER)(_Out_ PTP_TIMER* Timer,
    _In_ PTP_TIMER_CALLBACK  	Callback,
    _Inout_opt_ PVOID  	Context,
    _In_opt_ PTP_CALLBACK_ENVIRON  	CallbackEnviron
    );

typedef NTSTATUS(NTAPI* TPSETTIMER)(_Inout_ PTP_TIMER  	Timer,
    _In_opt_ PLARGE_INTEGER  	DueTime,
    _In_ LONG  	Period,
    _In_opt_ LONG  	WindowLength
    );

typedef ULONG LOGICAL;

typedef NTSTATUS(NTAPI* TPRELEASECLEANUPGROUPMEMBERS)(_Inout_ PTP_CLEANUP_GROUP  	CleanupGroup,
    _In_ LOGICAL  	CancelPendingCallbacks,
    _Inout_opt_ PVOID  	CleanupParameter
    );

HMODULE proxiedLoadLibraryA(LPCSTR libName) {
    BOOL bRet = FALSE;
    PTP_WORK work = NULL;
    PTP_TIMER timer = NULL;
    PTP_POOL pool = NULL;
    PTP_TIMER_CALLBACK timercallback = NULL;
    TP_CALLBACK_ENVIRON CallBackEnviron;
    PTP_CLEANUP_GROUP cleanupgroup = NULL;
    FILETIME FileDueTime;
    ULARGE_INTEGER ulDueTime;

    LOADLIBRARY_ARGS loadLibraryArgs = { 0 };
    loadLibraryArgs.pLoadLibraryA = (UINT_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    loadLibraryArgs.lpLibFileName = libName;

    FARPROC pTpAllocPool = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocPool");
    FARPROC pTpSetPoolMaxThreads = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpSetPoolMaxThreads");
    FARPROC pTpSetPoolMinThreads = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpSetPoolMinThreads");
    FARPROC pTpAllocCleanupGroup = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocCleanupGroup");
    FARPROC pTpAllocTimer = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocTimer");
    FARPROC pTpSetTimer = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpSetTimer");
    FARPROC pTpReleaseCleanupGroupMembers = GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpReleaseCleanupGroupMembers");

    if (!markCFGValid_nt((PVOID)CallbackStub))
    {
        puts("[!] Something went horribly wrong!");
        return 0;
    }
    printf("[+] Success! CFG Bypassed\n");

    InitializeThreadpoolEnvironment(&CallBackEnviron);

    // Create a custom, dedicated thread pool.
    ((TPALLOCPOOL)pTpAllocPool)(&pool, NULL);

    if (NULL == pool) {
        printf(("TpAllocPool failed. LastError: %u\n"),
            GetLastError());
    }

    // The thread pool is made persistent simply by setting
    // both the minimum and maximum threads to 1.
    ((TPSETPOOLMAXTHREADS)pTpSetPoolMaxThreads)(pool, 1);
    ((TPSETPOOLMINTHREADS)pTpSetPoolMinThreads)(pool, 1);

    // Create a cleanup group for this thread pool.
    ((TPALLOCCLEANUPGROUP)pTpAllocCleanupGroup)(&cleanupgroup);

    if (NULL == cleanupgroup) {
        printf(("CreateThreadpoolCleanupGroup failed. LastError: %u\n"),
            GetLastError());
    }

    // Create a timer with the same callback environment.
    ((TPALLOCTIMER)pTpAllocTimer)(&timer, (PTP_TIMER_CALLBACK)(unsigned char*)CallbackStub, &loadLibraryArgs, &CallBackEnviron);

    if (NULL == timer) {
        printf(("CreateThreadpoolTimer failed. LastError: %u\n"),
            GetLastError());
    }

    // Set the timer to fire in one second.
    ulDueTime.QuadPart = (ULONGLONG)-(1 * 10 * 1000 * 1000);
    FileDueTime.dwHighDateTime = ulDueTime.HighPart;
    FileDueTime.dwLowDateTime = ulDueTime.LowPart;

    // Conversion
    LARGE_INTEGER largeInt;
    largeInt.HighPart = FileDueTime.dwHighDateTime;
    largeInt.LowPart = FileDueTime.dwLowDateTime;

    ((TPSETTIMER)pTpSetTimer)(timer, &largeInt, 0, 0);

    Sleep(1500); // Delay for the timer to be fired

    // Wait for all callbacks to finish.
    // CloseThreadpoolCleanupGroupMembers also releases objects
    // that are members of the cleanup group, so it is not necessary 
    // to call close functions on individual objects 
    // after calling CloseThreadpoolCleanupGroupMembers.
    ((TPRELEASECLEANUPGROUPMEMBERS)pTpReleaseCleanupGroupMembers)(cleanupgroup, FALSE, NULL);

    return GetModuleHandleA(libName);  // Return the address of the loaded library
}

int main() {
    HMODULE user32 = proxiedLoadLibraryA("user32.dll");
    printf("user32.dll Address: %p\n", user32);
}