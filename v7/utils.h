//crt

typedef BOOLEAN(*func)(const PHANDLE_TABLE, const HANDLE, const PHANDLE_TABLE_ENTRY);
func ExDestroyHandle;

#define InRange(x, a, b) (x >= a && x <= b) 
#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))

template <typename StrType, typename StrType2>
_FI bool StrICmp(StrType Str, StrType2 InStr, bool Two) 
{
	
	#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)

	if (!Str || !InStr) return false;
	wchar_t c1, c2; do {
		c1 = *Str++; c2 = *InStr++;
		c1 = ToLower(c1); c2 = ToLower(c2);
		if (!c1 && (Two ? !c2 : 1)) 
			return true;
	} while (c1 == c2); 
	
	return false;
}

template <typename StrType>
_FI int StrLen(StrType Str)
{
	if (!Str) return 0;
	StrType Str2 = Str;
	while (*Str2) *Str2++;
	return (int)(Str2 - Str);
}

_FI VOID MemCpy(PVOID Dst, PVOID Src, ULONG Size) 
{
	__movsb((PUCHAR)Dst, (const PUCHAR)Src, Size);
}

_FI VOID MemZero(PVOID Ptr, SIZE_T Size)
{
	__stosb((PUCHAR)Ptr, 0, Size);
}

//memory
_FI PVOID MapNoCOW(PVOID Ptr, ULONG Size, PMDL* Mdl)
{
	*Mdl = IoAllocateMdl(Ptr, Size, false, false, nullptr);
	MmProbeAndLockPages(*Mdl, KernelMode, IoReadAccess);
	PVOID MapBuff = MmMapLockedPages(*Mdl, KernelMode);
	MmProtectMdlSystemAddress(*Mdl, PAGE_READWRITE);
	return MapBuff;
}

_FI VOID UnMapNoCOW(PVOID Ptr, PMDL Mdl)
{
	MmUnmapLockedPages(Ptr, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);
}

_FI PVOID UAlloc(ULONG Size)
{
	PVOID AllocBase = nullptr; SIZE_T SizeUL = SizeAlign(Size);
	ZwAllocateVirtualMemory(ZwCurrentProcess(), &AllocBase, 0, &SizeUL, MEM_COMMIT, PAGE_READWRITE);
	return AllocBase;
}

_FI VOID UFree(PVOID Ptr)
{
	SIZE_T SizeUL = 0;
	ZwFreeVirtualMemory(ZwCurrentProcess(), &Ptr, &SizeUL, MEM_RELEASE);
}

_FI PVOID KAlloc(ULONG Size, POOL_TYPE PoolType = POOL_TYPE::NonPagedPoolNx)
{
	PVOID Buff = ExAllocatePoolWithTag(PoolType, Size, 'KgxD');
	if (Buff) MemZero(Buff, Size); return Buff;
}

__forceinline void KFree(PVOID Ptr, ULONG Size = 0)
{
	if (Size)
		MemZero(Ptr, Size);
	ExFreePoolWithTag(Ptr, 'KgxD');
}

template<typename ReadType>
__forceinline ReadType Read(ULONG64 Addr)
{
	ReadType ReadData{};
	if (Addr && MmIsAddressValid((PVOID)Addr)) 
	{
		ReadData = *(ReadType*)Addr;
	}

	return ReadData;
}

__forceinline bool ReadArr(ULONG64 Addr, PVOID Buff, ULONG Size)
{
	if (MmIsAddressValid((PVOID)Addr)) 
	{
		MemCpy(Buff, (PVOID)Addr, Size);
		return true;
	}

	return false;
}

template<typename WriteType>
__forceinline void Write(ULONG64 Addr, WriteType Data)
{
	if (MmIsAddressValid((PVOID)Addr)) 
	{
		*(WriteType*)Addr = Data;
	}
}

__forceinline void WriteArr(ULONG64 Addr, PVOID Buff, ULONG Size) 
{
	if (MmIsAddressValid((PVOID)Addr)) 
	{
		MemCpy((PVOID)Addr, Buff, Size);
	}
}

PVOID PDEBase, PTEBase;

__forceinline PMMPTE GetPTEForVA(PVOID Address)
{
#define PHYSICAL_ADDRESS_BITS 40
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PTE_SHIFT 3
	PMMPTE PDE = (PMMPTE)(((((ULONG64)Address >> PDI_SHIFT) << PTE_SHIFT) & 0x3FFFFFF8ull) + (ULONG64)PDEBase);

	if (PDE->u.Hard.LargePage)
		return PDE;

	return (PMMPTE)(((((ULONG64)Address >> PTI_SHIFT) << PTE_SHIFT) & 0x7FFFFFFFF8ull) + (ULONG64)PTEBase);
}
// Allocation Virtual Memory
PVOID AllocateMemory(SIZE_T Size)
{
	size_t AllocSize = SizeAlign(Size);
	PVOID Base = nullptr;

	ZwAllocateVirtualMemory(ZwCurrentProcess(), &Base, 0, &AllocSize, MEM_COMMIT, PAGE_READWRITE);

	if (Base)
	{
		//pte patch
		for (size_t i = 0; i < AllocSize; i += PAGE_SIZE)
		{
			const auto Addr = (uintptr_t)Base + i;
			*(volatile uintptr_t*)(Addr);
			GetPTEForVA((PVOID)Addr)->u.Hard.NoExecute = false;
		}
	}

	return Base;
}

void FreeMemory(PVOID Address, SIZE_T Size)
{
	uintptr_t SizeUL64 = SizeAlign(Size);

	if (!SizeUL64)
		ZwFreeVirtualMemory(ZwCurrentProcess(), (void**)&Address, &SizeUL64, MEM_RELEASE);
	else
		ZwFreeVirtualMemory(ZwCurrentProcess(), (void**)&Address, &SizeUL64, MEM_DECOMMIT);
}


ULONG ProtectMemory(ULONG64 Address, SIZE_T Size, ULONG NewProtect)
{
	ULONG OldProtection = 0;
	PVOID Addr1 = (PVOID)Address;
	NTSTATUS Status = ZwProtectVirtualMemory(ZwCurrentProcess(), &Addr1, &Size, NewProtect, &OldProtection);

//	DbgPrint("[FACE] Protect: Status: 0x%p | Address: 0x%p | New Protect: 0x%p | Old: 0x%p\n", Status, Address, NewProtect, OldProtection);

	return OldProtection;
}

//main utils
_FI VOID Sleep(LONG64 MSec) 
{
	LARGE_INTEGER Delay; Delay.QuadPart = -MSec * 10000;
	KeDelayExecutionThread(KernelMode, false, &Delay);
}

template<typename Ret, typename... Args>
Ret __forceinline CallPtr(PVOID Addr, Args... Vars) 
{
	return ((Ret(__fastcall*)(...))Addr)(Vars...);
}

PVOID NQSI(SYSTEM_INFORMATION_CLASS Class)
{
	//get alloc size
	NewTry: ULONG ReqSize = 0; 
	ZwQuerySystemInformation(Class, nullptr, ReqSize, &ReqSize);
	if (!ReqSize) goto NewTry; 
	
	//call QuerySystemInfo
	PVOID pInfo = KAlloc(ReqSize);
	if (!NT_SUCCESS(ZwQuerySystemInformation(Class, pInfo, ReqSize, &ReqSize))) {
		KFree(pInfo); goto NewTry;
	}

	//ret data
	return pInfo;
}

//pe utils
PVOID FindSection(PVOID ModBase, const char* Name, PULONG SectSize)
{
	//get & enum sections
	PIMAGE_NT_HEADERS NT_Header = NT_HEADER(ModBase);
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Header);
	for (PIMAGE_SECTION_HEADER pSect = Sect; pSect < Sect + NT_Header->FileHeader.NumberOfSections; pSect++)
	{
		//fix section name
		char SectName[9]; SectName[8] = 0;
		MemCpy(SectName, pSect->Name, 8);

		//check name
		if (StrICmp(SectName, Name, true))
		{
			//save size
			if (SectSize) {
				ULONG SSize = SizeAlign(max(pSect->Misc.VirtualSize, pSect->SizeOfRawData));
				*SectSize = SSize;
			}

			//ret full sect ptr
			return (PVOID)((ULONG64)ModBase + pSect->VirtualAddress);
		}
	}

	return nullptr;
}

PUCHAR FindPatternSect(PVOID ModBase, const char* SectName, const char* Pattern)
{
	ULONG SectSize;
	PUCHAR ModuleStart = (PUCHAR)FindSection(ModBase, SectName, &SectSize);
	PUCHAR ModuleEnd = ModuleStart + SectSize;

	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');
		if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
			if (!FirstMatch) FirstMatch = ModuleStart;
			SkipByte ? CurPatt += 2 : CurPatt += 3;
			if (CurPatt[-1] == 0) return FirstMatch;
		}

		else if (FirstMatch) {
			ModuleStart = FirstMatch;
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	return nullptr;
}

PUCHAR FindPattern_Wrapper(const char* Pattern, ULONG64 Module1)
{
	PUCHAR ModuleStart = (PUCHAR)Module1;
	if (!ModuleStart)
		return nullptr;
	PIMAGE_NT_HEADERS NtHeader = ((PIMAGE_NT_HEADERS)(ModuleStart + ((PIMAGE_DOS_HEADER)ModuleStart)->e_lfanew));
	PUCHAR ModuleEnd = (PUCHAR)(ModuleStart + NtHeader->OptionalHeader.SizeOfImage);

	//scan pattern main
	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');
		if (SkipByte || *ModuleStart == GetByte(CurPatt))
		{
			if (!FirstMatch)
				FirstMatch = ModuleStart;
			SkipByte ? CurPatt += 2 : CurPatt += 3;
			if (CurPatt[-1] == 0)
				return FirstMatch;
		}

		else if (FirstMatch)
		{
			ModuleStart = FirstMatch;
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	return nullptr;
}

bool CompareByteArray(PBYTE Data, PBYTE Signature)
{
	for (; *Signature; ++Signature, ++Data)
	{
		if (*Signature == '\x00')
		{
			continue;
		}
		if (*Data != *Signature)
		{
			return false;
		}
	}
	return true;
}

PBYTE FindSignature(PBYTE BaseAddress, ULONG ImageSize, PBYTE Signature)
{
	BYTE First = Signature[0];
	PBYTE Max = BaseAddress + ImageSize - StrLen((PCHAR)Signature);

	for (; BaseAddress < Max; ++BaseAddress)
	{
		if (*BaseAddress != First)
		{
			continue;
		}
		if (CompareByteArray(BaseAddress, Signature))
		{
			return BaseAddress;
		}
	}
	return NULL;
}

PVOID GetProcAdress(PVOID ModBase, const char* Name)
{
	//parse headers
	PIMAGE_NT_HEADERS NT_Head = NT_HEADER(ModBase);
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);

	//process records
	for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
	{
		//get ordinal & name
		USHORT Ordinal = ((USHORT*)((ULONG64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
		const char* ExpName = (const char*)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames))[i];

		//check export name
		if (StrICmp(Name, ExpName, true))
			return (PVOID)((ULONG64)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfFunctions))[Ordinal]);
	}

	//no export
	return nullptr;
}

//process mgr
_FI PEPROCESS AttachToProcess(HANDLE PID)
{
	//get eprocess
	PEPROCESS Process = nullptr;
	if (PsLookupProcessByProcessId(PID, &Process) || !Process)
		return nullptr;

	//take process lock
	if (PsAcquireProcessExitSynchronization(Process))
	{
		//process lock failed
		ObfDereferenceObject(Process);
		return nullptr;
	}

	//attach to process
	KeAttachProcess(Process);
	return Process;
}

_FI VOID DetachFromProcess(PEPROCESS Process)
{
	//check valid process
	if (Process != nullptr)
	{
		//de-attach to process
		KeDetachProcess();

		//cleanup & process unlock
		ObfDereferenceObject(Process);
		PsReleaseProcessExitSynchronization(Process);
	}
}

template <typename A>
__forceinline bool IsAddressValid(A Address)
{
	return MmIsAddressValid((PVOID)Address);
}

namespace Test
{
	__forceinline PEPROCESS KiSwapProcess(PEPROCESS NewProcess)
	{
		auto CurrentThread = KeGetCurrentThread();
		auto ApcState = *(ULONG64*)((ULONG64)CurrentThread + 0x98);
		auto OldProcess = *(PEPROCESS*)(ApcState + 0x20);
		*(PEPROCESS*)(ApcState + 0x20) = NewProcess;
		auto DirectoryTableBase = *(ULONG64*)((ULONG64)NewProcess + 0x28);
		__writecr3(DirectoryTableBase);
		return OldProcess;
	}

	PVOID GetUserModuleBase(PEPROCESS Process, const char* ModName, ULONG* ModSize = nullptr)
	{
		PPEB PPEB = PsGetProcessPeb(Process);

		if (IsAddressValid(PPEB))
		{
			PEB PEB_Data;
			MemCpy(&PEB_Data, PPEB, sizeof(PEB));

			if (IsAddressValid(PEB_Data.Ldr))
			{
				PEB_LDR_DATA Ldr;
				MemCpy(&Ldr, PEB_Data.Ldr, sizeof(PEB_LDR_DATA));

				PLIST_ENTRY LdrListHead = Ldr.InLoadOrderModuleList.Flink;
				PLIST_ENTRY LdrCurrentNode = Ldr.InLoadOrderModuleList.Flink;

				if (IsAddressValid(LdrListHead))
				{
					do
					{
						LDR_DATA_TABLE_ENTRY ListEntry;
						MemCpy(&ListEntry, LdrCurrentNode, sizeof(LDR_DATA_TABLE_ENTRY));

						if (ListEntry.BaseDllName.Length > 0 && StrICmp(ModName, ListEntry.BaseDllName.Buffer, true))
						{
							if (ModSize)
								*ModSize = ListEntry.SizeOfImage;

							return ListEntry.DllBase;
						}

						LdrCurrentNode = ListEntry.InLoadOrderLinks.Flink;
					} while (LdrListHead != LdrCurrentNode);
				}
			}
		}

		return nullptr;
	}

	PEPROCESS GetProcess(const char* ProcName)
	{
		PEPROCESS EProc = nullptr;
		PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)NQSI(SystemProcessInformation), pInfoCur = pInfo;

		while (true)
		{
			const wchar_t* ProcessName = pInfoCur->ImageName.Buffer;
			if (IsAddressValid((PVOID)ProcessName))
			{
				if (StrICmp(ProcName, ProcessName, true))
				{
					if (!PsLookupProcessByProcessId(pInfoCur->UniqueProcessId, &EProc))
						break;
				}
			}

			if (!pInfoCur->NextEntryOffset)
				break;

			pInfoCur = (PSYSTEM_PROCESS_INFO)((ULONG64)pInfoCur + pInfoCur->NextEntryOffset);
		}

		KFree(pInfo);
		return EProc;
	}
}

//void NTAPI InitializeKBlock(KDDEBUGGER_DATA64* DebuggerDataBlock)
//{
//	CONTEXT Context = { 0 };
//	Context.ContextFlags = CONTEXT_FULL;
//	RtlCaptureContext(&Context);
//
//	DUMP_HEADER* pDumpHeader = (DUMP_HEADER*)ExAllocatePool(NonPagedPool, DUMP_BLOCK_SIZE);
//
//	if (pDumpHeader)
//	{
//		KeCapturePersistentThreadState(&Context, NULL, 0, 0, 0, 0, 0, pDumpHeader);
//		memcpy(DebuggerDataBlock, (PUCHAR)pDumpHeader + KDDEBUGGER_DATA_OFFSET, sizeof(*DebuggerDataBlock));
//
//		ExFreePoolWithTag(pDumpHeader, 0);
//	}
//}

PVOID GetUserModuleBase(PEPROCESS Process, const char* ModName)
{
	if (IoIs32bitProcess(nullptr)) 
	{
		PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(Process);
		if (!pPeb32 || !pPeb32->Ldr) return nullptr;

		for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
			pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
			pListEntry = (PLIST_ENTRY32)pListEntry->Flink) {
			PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
			if (StrICmp(ModName, (PWCH)pEntry->BaseDllName.Buffer, false))
				return (PVOID)pEntry->DllBase;
		}
	}
	else {
		PPEB PEB = PsGetProcessPeb(Process);
		if (!PEB || !PEB->Ldr) return nullptr;

		for (PLIST_ENTRY pListEntry = PEB->Ldr->InLoadOrderModuleList.Flink;
			pListEntry != &PEB->Ldr->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (StrICmp(ModName, pEntry->BaseDllName.Buffer, false))
				return pEntry->DllBase;
		}
	}

	return nullptr;
}

PVOID GetImportTableEntry(PEPROCESS Process, const char* Module, const char* Import)
{
	PVOID ModBase = Test::GetUserModuleBase(Process, Module);

	if (!ModBase)
	{
		return nullptr;
	}

	IMAGE_DOS_HEADER dosHeader = { 0 };
	_IMAGE_NT_HEADERS64 ntHeaders = { 0 };
	
	if (!ReadArr((ULONG64)ModBase, &dosHeader, sizeof(dosHeader)))
		return nullptr;

	ReadArr((ULONG64)ModBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders));

	ULONG ImportDescriptorOffset = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (!ImportDescriptorOffset)
		return nullptr;

	for (;; ImportDescriptorOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
	{
		IMAGE_IMPORT_DESCRIPTOR importDescriptor = { 0 };

		ReadArr((ULONG64)ModBase + ImportDescriptorOffset, &importDescriptor, sizeof(importDescriptor));

		auto thunkOffset = importDescriptor.OriginalFirstThunk;
		if (!thunkOffset)
		{
			break;
		}

		for (ULONG i = 0UL; ; thunkOffset += sizeof(IMAGE_THUNK_DATA64), ++i)
		{
			IMAGE_THUNK_DATA64 thunk = { 0 };
			ReadArr((ULONG64)ModBase + thunkOffset, &thunk, sizeof(thunk));

			if (!thunk.u1.AddressOfData)
				break;

			CHAR name[0xFF] = { 0 };
			ReadArr((ULONG64)ModBase + thunk.u1.AddressOfData + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name), name, sizeof(name));

			if (StrICmp(name, Import, true))
			{
				return (PVOID)((ULONG64)ModBase + importDescriptor.FirstThunk + (i * sizeof(PVOID)));
			}
		}
	}

	return nullptr;
}

PEPROCESS GetProcessWModule(const char* ProcName, const char* ModName, PVOID* WaitModBase)
{
	//get process list
	PEPROCESS EProc = nullptr;
	PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)NQSI(SystemProcessInformation), pInfoCur = pInfo;

	while (true)
	{
		//get process name
		const wchar_t* ProcessName = pInfoCur->ImageName.Buffer;
		if (IsAddressValid((PVOID)ProcessName))
		{
			//check process name
			if (StrICmp(ProcName, ProcessName, true))
			{
				//attach to process
				PEPROCESS Process = AttachToProcess(pInfoCur->UniqueProcessId);
				if (Process != nullptr)
				{
					//check wait module
					PVOID ModBase = GetUserModuleBase(Process, ModName);
					if (ModBase)
					{
						//save modbase
						if (WaitModBase)
							*WaitModBase = ModBase;

						//save eprocess
						EProc = Process;
						break;
					}

					//failed, no wait module
					DetachFromProcess(Process);
				}
			}
		}

		//goto next process entry
		if (!pInfoCur->NextEntryOffset) break;
		pInfoCur = (PSYSTEM_PROCESS_INFO)((ULONG64)pInfoCur + pInfoCur->NextEntryOffset);
	}

	//cleanup
	KFree(pInfo);
	return EProc;
}

PVOID GetKernelModuleBase(const char* ModName)
{
	//get module list
	PSYSTEM_MODULE_INFORMATION ModuleList = (PSYSTEM_MODULE_INFORMATION)NQSI(SystemModuleInformation);

	//process module list
	PVOID ModuleBase = 0;
	for (ULONG64 i = 0; i < ModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE Module = ModuleList->Modules[i];
		if (StrICmp(&Module.ImageName[Module.ModuleNameOffset], ModName, true)) {
			ModuleBase = Module.Base;
			break;
		}
	}

	//cleanup
	KFree(ModuleList);
	return ModuleBase;
}

void CallUserMode(PVOID Func)
{
	//get user32 (KernelCallbackTable table ptr)
	PEPROCESS Process = IoGetCurrentProcess();
	PVOID ModBase = GetUserModuleBase(Process, E("user32"));
	PVOID DataSect = FindSection(ModBase, E(".data"), nullptr);
	ULONG64 AllocPtr = ((ULONG64)DataSect + 0x2000 - 0x8);
	ULONG64 CallBackPtr = (ULONG64)PsGetProcessPeb(Process)->KernelCallbackTable;
	ULONG Index = (ULONG)((AllocPtr - CallBackPtr) / 8);

	//store func ptr in place
	auto OldData = _InterlockedExchangePointer((PVOID*)AllocPtr, Func);

	//enable apc (FIX BSOD)
	//ImpCall(KeLeaveGuardedRegion);

	//call usermode
	union Garbage { ULONG ulong; PVOID pvoid; } Garbage;
	KeUserModeCallback(Index, nullptr, 0, &Garbage.pvoid, &Garbage.ulong);

	//store old ptr in place
	_InterlockedExchangePointer((PVOID*)AllocPtr, OldData);

	//disable apc
	//ImpCall(KeEnterGuardedRegion);
}

PVOID MmAllocateIndependentPages(PVOID KBase, ULONG64 PageCount)
{
	auto MiSystemPartition = RVA(FindPatternSect(KBase, E(".text"), E("0F 85 ? ? ? ? 48 8D 05 ? ? ? ? 4C 3B D0")), 13);
	auto MiGetPage = (PVOID)RVA(FindPatternSect(KBase, E(".text"), E("8B D3 E8 ? ? ? ? 48 83 F8 FF")), 7);
	auto MiRemovePhysicalMemory = (PVOID)RVA(FindPatternSect(KBase, E(".text"), E("44 8D 42 32 E8 ? ? ? ?")), 9);

	auto MiSystemPteInfo = RVA(FindPatternSect(KBase, E(".text"), E("4C 2B D1 48 8D 0D ? ? ? ?")), 10);
	auto MiReservePtes = (PVOID)RVA(FindPatternSect(KBase, E(".text"), E("48 8B 80 ? ? ? ? 48 89 45 ? E8 ? ? ? ?")), 16);

	auto PfnBase = *(ULONG64*)RVA(FindPatternSect(KBase, E(".text"), E("48 8B 3D ? ? ? ? 48 C1 EF 09")), 7);
	auto MiInitializePfn = (PVOID)RVA(FindPatternSect(KBase, E(".text"), E("E8 ? ? ? ? 0F BA EB 1D")), 5);

	MMPTE* PTE = CallPtr<MMPTE*>(MiReservePtes, MiSystemPteInfo, PageCount);

	if (!PTE) return nullptr;

#define PTE_SHIFT 3
#define VA_SHIFT (63 - 47)
#define MiGetVirtualAddressMappedByPte(PTE) ((PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - (ULONG64)PTEBase) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))


	PVOID MappedVA = MiGetVirtualAddressMappedByPte(PTE);

	for (SIZE_T i = 0; i < PageCount; i++)
	{
	NewTry:
		auto PFN = CallPtr<ULONG64>(MiGetPage, MiSystemPartition, 0ull, 8ull);

		if (PFN == -1) goto NewTry;

		ULONG64 PfnSize = 0x1000; PfnSize = PfnSize >> 12;
		CallPtr<void>(MiRemovePhysicalMemory, PFN, PfnSize);

		PTE->u.Hard.Valid = 1;
		PTE->u.Hard.Owner = 0; //0 km, 1 um
		PTE->u.Hard.Write = 1;
		PTE->u.Hard.NoExecute = 0;
		PTE->u.Hard.PageFrameNumber = PFN;

		++PTE;
	}

	return MappedVA;
}

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(const ULONG64* pHandleTable, const LONGLONG Handle)
{
	ULONGLONG v2; // rdx
	LONGLONG v3; // r8

	v2 = Handle & 0xFFFFFFFFFFFFFFFC;
	if (v2 >= *pHandleTable)
		return 0;
	v3 = *(pHandleTable + 1);
	if ((v3 & 3) == 1)
		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 10) - 1) + 4 * (v2 & 0x3FF));
	if ((v3 & 3) != 0)
		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF)) + 4 * (v2 & 0x3FF));
	return reinterpret_cast<PHANDLE_TABLE_ENTRY>(v3 + 4 * v2);
}

//void RemovePspCidTableEntry(const ULONG64* pPspCidTable, const HANDLE threadId)
//{
//	ULONG64* pHandleTable = reinterpret_cast<ULONG64*>(*pPspCidTable);
////	DbgPrintEx(0, 0, "[FACE] pHandleTable: %p", pHandleTable);
//	
//	const PHANDLE_TABLE_ENTRY pCidEntry = ExpLookupHandleTableEntry(pHandleTable, reinterpret_cast<LONGLONG>(threadId));
//
//	if (pCidEntry != NULL)
//	{
////		DbgPrintEx(0, 0, "[FACE] pCidEntry: %p", pCidEntry);
////		DbgPrintEx(0, 0, "[FACE] CidEntry->ObjectPointerBits: %p", pCidEntry->ObjectPointerBits);
//
//		ExDestroyHandle(reinterpret_cast<PHANDLE_TABLE>(pHandleTable), threadId, pCidEntry);
//
//		if (pCidEntry->ObjectPointerBits == 0)
//		{
////			DbgPrintEx(0, 0, "[FACE] ObjectPointerBits is NULL");
////			DbgPrintEx(0, 0, "[FACE] pCidEntry->ObjectPointerBits: %p", pCidEntry->ObjectPointerBits);
//		}
//	}
//}