#include "global.h"
#include <cstdint>

#pragma code_seg(push)
#pragma code_seg("INIT")

//tmp hook data
PVOID* xKdEnumerateDebuggingDevicesPtr;
PVOID xKdEnumerateDebuggingDevicesVal;
#define DllName DynamicSwapchainDXGI

NTSTATUS DriverEntry(PVOID a1, PVOID a2)
{
	UNREFERENCED_PARAMETER(a1);
	PVOID KBase = a2;
	if (KBase == nullptr)
	{
		return 0xDEAD1;
	}
	ULONG64 PTE = (ULONG64)FindPatternSect(KBase, E(".text"), E("48 23 C8 48 B8 ? ? ? ? ? ? ? ? 48 03 C1 C3"));
	PTE = *(ULONG64*)(PTE + 5);
	ULONGLONG Mask = (1ll << (PHYSICAL_ADDRESS_BITS - 1)) - 1;
	PDEBase = PVOID((PTE & ~Mask) | ((PTE >> 9) & Mask));
	PTEBase = PVOID(PTE);

WaitProcess:
	PEPROCESS TargetProcess = Test::GetProcess(E("EscapeFromTarkov.exe")); //EscapeFromTarkov RustClient

	if (!TargetProcess)
	{
		Sleep(200);
		goto WaitProcess;
	}

	Sleep(30000);

	PEPROCESS CurrentProcess = Test::KiSwapProcess(TargetProcess);

	Globals::m_LastProcess = TargetProcess;

	PVOID Kernel32 = Test::GetUserModuleBase(TargetProcess, E("Kernel32.dll"));

	PVOID LLA = GetProcAdress(Kernel32, E("LoadLibraryA"));
	PVOID GPA = GetProcAdress(Kernel32, E("GetProcAddress"));

	//parse dll
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)DllName;
	PIMAGE_NT_HEADERS DllNtHeader = NT_HEADER(DllName);

	PVOID pRemoteBase = AllocateMemory(DllNtHeader->OptionalHeader.SizeOfImage);

	if (!pRemoteBase)
	{
		Test::KiSwapProcess(CurrentProcess);
		return (NTSTATUS)1;
	}

	RelocateImage(DllNtHeader, pRemoteBase, DllName);
	SectionsMgr(DllNtHeader, pRemoteBase, DllName);

	loaderdata LoaderParams = {};
	LoaderParams.fnGetProcAddress = (pGetProcAddress)GPA;
	LoaderParams.fnLoadLibraryA = (pLoadLibraryA)LLA;
	LoaderParams.ImageBase = (ULONG64)pRemoteBase;
	LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((ULONG64)pRemoteBase + (ULONG64)pDosHeader->e_lfanew);

	LoaderParams.OEP = DllNtHeader->OptionalHeader.AddressOfEntryPoint;
	LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)pRemoteBase + DllNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	PVOID pRemoteLoaderData = AllocateMemory(sizeof(loaderdata));
	WriteArr((ULONG64)pRemoteLoaderData, &LoaderParams, sizeof(loaderdata));

	PUCHAR Executor = DummyExecutor;
	//parse dll
	PIMAGE_NT_HEADERS MDllNtHeader = NT_HEADER(Executor);

	ULONG Offset = 0x5C9 + 2; // Skip [mov rax,]

	ULONG64 PathPlace = (ULONG64)Executor + Offset;

	*(DWORD64*)PathPlace = (DWORD64)pRemoteLoaderData;

	PVOID pMRemoteBase = AllocateMemory(MDllNtHeader->OptionalHeader.SizeOfImage);

	if (!pMRemoteBase)
		return false;

	RelocateImage(MDllNtHeader, pMRemoteBase, Executor);

	SectionsMgr(MDllNtHeader, pMRemoteBase, Executor);

	PVOID EPoint = (PVOID)((ULONG64)pMRemoteBase + MDllNtHeader->OptionalHeader.AddressOfEntryPoint);

	PVOID ImportEntry = GetImportTableEntry(Globals::m_LastProcess, E("user32.dll"), E("NtUserGetForegroundWindow"));

	if (!ImportEntry)
		return false;

	*reinterpret_cast<PVOID*>(&x64Executor[3]) = ImportEntry;
	*reinterpret_cast<PVOID*>(&x64Executor[46]) = (PVOID)EPoint;

	ReadArr((uintptr_t)ImportEntry, &x64Executor[13], sizeof(PVOID));
	unsigned char* pMappedShellcode = reinterpret_cast<unsigned char*>(AllocateMemory(sizeof(x64Executor)));

	if (!pMappedShellcode)
		return false;

	WriteArr((uintptr_t)pMappedShellcode, x64Executor, sizeof(x64Executor));

	ProtectMemory((uintptr_t)ImportEntry, sizeof(ImportEntry), PAGE_READWRITE);

	auto ShellCodeEntry = pMappedShellcode + 1;

	WriteArr((uintptr_t)ImportEntry, &ShellCodeEntry, sizeof(ShellCodeEntry));

	Test::KiSwapProcess(CurrentProcess);

	return STATUS_ACCESS_DENIED;
}
#pragma code_seg(pop)