#include "CFG.h"

#pragma comment(lib, "WindowsApp")

BOOL markCFGValid_nt(PVOID pAddress)
{
	ULONG dwOutput = 0;
	NTSTATUS ntStatus = 0;
	MEMORY_BASIC_INFORMATION mbi;
	VM_INFORMATION tVmInformation = { 0 };

	MEMORY_RANGE_ENTRY tVirtualAddresses = { 0 };
	CFG_CALL_TARGET_INFO OffsetInformation = { 0 };

	MyNtSetInformationVirtualMemory pNtSetInformationVirtualMemory = (MyNtSetInformationVirtualMemory)GetProcAddress(GetModuleHandle((LPWSTR)L"ntdll.dll"), (LPCSTR)"NtSetInformationVirtualMemory");
	MyNtQueryVirtualMemory pNtQueryVirtualMemory = (MyNtQueryVirtualMemory)GetProcAddress(GetModuleHandle((LPWSTR)L"ntdll.dll"), (LPCSTR)"NtQueryVirtualMemory");

	NTSTATUS status = pNtQueryVirtualMemory(NtCurrentProcess(), pAddress, MemoryBasicInformation, &mbi, sizeof(mbi), 0);
	if (!NT_SUCCESS(status))
		return FALSE;

	if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE)
	{
		return FALSE;
	}

	OffsetInformation.Offset = (ULONG_PTR)pAddress - (ULONG_PTR)mbi.BaseAddress;
	OffsetInformation.Flags = CFG_CALL_TARGET_VALID;

	tVirtualAddresses.NumberOfBytes = (SIZE_T)mbi.RegionSize;
	tVirtualAddresses.VirtualAddress = (PVOID)mbi.BaseAddress;

	tVmInformation.dwNumberOfOffsets = 0x1;
	tVmInformation.plOutput = &dwOutput;
	tVmInformation.ptOffsets = &OffsetInformation;
	tVmInformation.pMustBeZero = 0x0;
	tVmInformation.pMoarZero = 0x0;

	printf("[+] Calling NtSetInformationVirtualMemory...");
	ntStatus = pNtSetInformationVirtualMemory(NtCurrentProcess(), VmCfgCallTargetInformation, 1, &tVirtualAddresses, (PVOID)&tVmInformation, (ULONG)sizeof(tVmInformation));
	if (!NT_SUCCESS(ntStatus))
	{
		//STATUS_INVALID_PAGE_PROTECTION , CFG isn't enabled on the process
		if (0xC0000045 != ntStatus)
			return FALSE;
	}

	return TRUE;

}