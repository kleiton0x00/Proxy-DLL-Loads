#include <Windows.h>
#include <stdio.h>

// Module to load, change to your liking
static LPCSTR moduleName = "user32.dll";

// Exception handler function
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    // Check for STATUS_GUARD_PAGE_VIOLATION
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        // Get the address of "LoadLibraryA"
        FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        // Set RIP register to the address of "LoadLibraryA"
        ExceptionInfo->ContextRecord->Rip = (DWORD64)loadLibraryAddr;
        // RCX hold the argument (library name)
        ExceptionInfo->ContextRecord->Rcx = (DWORD64)moduleName;

        // Resume execution
        return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
    }

    // Continue searching for other exception handlers
    return EXCEPTION_CONTINUE_SEARCH;
}

HMODULE proxiedLoadLibraryA(LPCSTR libName)
{
    // Just something to get its address to trigger the VEH
    void(WINAPI* o_Sleep)(DWORD dwMilliseconds) = Sleep;

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
}
