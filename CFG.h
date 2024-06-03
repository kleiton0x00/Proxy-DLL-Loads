#pragma once
#include <windows.h>
#include <stdio.h>

#define CFG_CALL_TARGET_VALID (0x00000001)
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

BOOL markCFGValid_nt(PVOID pvAddress);

typedef struct _VM_INFORMATION
{
	DWORD					dwNumberOfOffsets;
	PULONG					plOutput;
	PCFG_CALL_TARGET_INFO	ptOffsets;
	PVOID					pMustBeZero;
	PVOID					pMoarZero;

} VM_INFORMATION, * PVM_INFORMATION;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

typedef LONG(NTAPI* MyNtSetInformationVirtualMemory)(
	HANDLE                           hProcess,
	VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
	ULONG_PTR                        NumberOfEntries,
	PMEMORY_RANGE_ENTRY              VirtualAddresses,
	PVOID                            VmInformation,
	ULONG                            VmInformationLength
	);


typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef LONG(NTAPI* MyNtQueryVirtualMemory)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);