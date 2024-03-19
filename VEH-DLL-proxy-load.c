#include <windows.h>
#include <stdio.h>

typedef BOOL(WINAPI* fnCheckGadget)						(PVOID);

// Module to load, change to your liking
static LPCSTR moduleName = "winhttp.dll";

PVOID FindGadget(PVOID pModule, fnCheckGadget CallbackCheck)
{
    for (int i = 0;; i++)
    {
        if (CallbackCheck((PVOID)((UINT_PTR)pModule + i)))
            return (PVOID)((UINT_PTR)pModule + i);
    }
}

BOOL fnGadgetJmpRax(PVOID pAddr)
{

    if (
        ((PBYTE)pAddr)[0] == 0xFF &&
        ((PBYTE)pAddr)[1] == 0xe0
        )
        return TRUE;
    else
        return FALSE;
}

// Exception handler function
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    // Check for STATUS_GUARD_PAGE_VIOLATION
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        // Get the address of "LoadLibraryA"
        FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        // Set RAX register to the address of "LoadLibraryA"
        ExceptionInfo->ContextRecord->Rax = (DWORD64)loadLibraryAddr;

        // Jump to RAX via ROP Gadget
        PVOID pNtdll = GetModuleHandleA("kernel32.dll");
        PVOID pJmpRaxGadget = FindGadget(pNtdll, fnGadgetJmpRax);
        ExceptionInfo->ContextRecord->Rip = (DWORD64)pJmpRaxGadget;

        // RCX holds the argument (library name)
        ExceptionInfo->ContextRecord->Rcx = (DWORD64)moduleName;

        // Resume execution
        return EXCEPTION_CONTINUE_EXECUTION; // Continue to the next instruction
    }

    // Continue searching for other exception handlers
    return EXCEPTION_CONTINUE_SEARCH;
}

HMODULE proxiedLoadLibraryA(LPCSTR libName)
{
    // Just something to get its address to trigger the VEH
    void(WINAPI * o_Sleep)(DWORD dwMilliseconds) = Sleep;

    // Install the Vectored Exception Handler
    PVOID handler = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    if (!handler)
    {
        fprintf(stderr, "Failed to install Vectored Exception Handler\n");
        return nullptr;
    }

    // Triggering the VEH by setting page to PAGE_GUARD
    DWORD oldProtection = 0;
    VirtualProtect((LPVOID)Sleep, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtection);

    // The module got loaded, so retrieve its base address
    HMODULE addr = GetModuleHandleA(moduleName);

    // Remove the Vectored Exception Handler
    RemoveVectoredExceptionHandler(handler);

    return addr;
}

int main() {
    HMODULE user32 = proxiedLoadLibraryA(moduleName);
    printf("%s Address: %p\n", moduleName, user32);
    getchar();
}
