_FI PVOID RVA_VA(ULONG64 RVA, PIMAGE_NT_HEADERS NT_Header, PVOID LocalImg)
{
	//get data ptr
	PIMAGE_SECTION_HEADER FirstSect = IMAGE_FIRST_SECTION(NT_Header);
	for (PIMAGE_SECTION_HEADER CurSect = FirstSect; CurSect < FirstSect + NT_Header->FileHeader.NumberOfSections; CurSect++)
		if (RVA >= CurSect->VirtualAddress && RVA < CurSect->VirtualAddress + CurSect->Misc.VirtualSize)
			return (void*)((uintptr_t)LocalImg + CurSect->PointerToRawData + (RVA - CurSect->VirtualAddress));
	
	//failed
	return nullptr;
}

_FI VOID RelocateImage(PIMAGE_NT_HEADERS NT_Header, PVOID RemoteImg, PVOID LocalImg)
{
	//get relocation data
	LONG64 DeltaOffset = (uintptr_t)RemoteImg - NT_Header->OptionalHeader.ImageBase; if (!DeltaOffset) return;
	typedef struct RelocEntry { ULONG RVA, Size; struct { USHORT Offset : 12; USHORT Type : 4; } Item[1]; } *pRelocEntry;
	pRelocEntry RelocEnt = (pRelocEntry)RVA_VA(NT_Header->OptionalHeader.DataDirectory[5].VirtualAddress, NT_Header, LocalImg);
	uintptr_t RelocEnd = (uintptr_t)RelocEnt + NT_Header->OptionalHeader.DataDirectory[5].Size;
	if (!RelocEnt || (uintptr_t)RelocEnt == RelocEnd) return;

	//process reloc table
	while ((uintptr_t)RelocEnt < RelocEnd && RelocEnt->Size)
	{
		//get records count & process reloc records
		ULONG RecordsCount = (RelocEnt->Size - 8) >> 1;
		for (ULONG i = 0; i < RecordsCount; i++)
		{
			//get fixup type & shift delta
			USHORT FixType = RelocEnt->Item[i].Type;
			USHORT ShiftDelta = (RelocEnt->Item[i].Offset) % 4096;

			//fixup reloc
			if (FixType == IMAGE_REL_BASED_HIGHLOW || FixType == IMAGE_REL_BASED_DIR64) {
				uintptr_t FixVA = (uintptr_t)RVA_VA(RelocEnt->RVA, NT_Header, LocalImg);
				if (!FixVA) continue; //relocation out of sections
				*(uintptr_t*)(FixVA + ShiftDelta) += DeltaOffset;
			}
		}

		//goto next reloc block
		RelocEnt = (pRelocEntry)((uintptr_t)RelocEnt + RelocEnt->Size);
	}
}

_FI VOID SectionsMgr(PIMAGE_NT_HEADERS NT_Header, PVOID RemoteImg, PVOID LocalImg)
{
	//process sections & free pe headers
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Header);
	for (USHORT Cnt = 0; Cnt < NT_Header->FileHeader.NumberOfSections; Cnt++, Sect++)
	{
		//get section info
		ULONG VA_Size = SectSize(Sect);
		PVOID VA_Addr = (PVOID)((ULONG64)RemoteImg + Sect->VirtualAddress);

		//wipe section
		MemZero(VA_Addr, VA_Size);

		//write section
		if (Sect->SizeOfRawData)
		{
			MemCpy(VA_Addr, (PUCHAR)LocalImg + Sect->PointerToRawData, Sect->SizeOfRawData);
			//DbgPrint("[FACE] Writed %s section\n", Sect->Name);
		}
	}
}

/*FIXME*/
_FI BOOLEAN ResolveImport(PEPROCESS Process, PIMAGE_NT_HEADERS NT_Header, PVOID LocalImg)
{
	//get import data & check valid
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVA_VA(
		NT_Header->OptionalHeader.DataDirectory[1].VirtualAddress, NT_Header, LocalImg);
	if (!ImportDesc || !NT_Header->OptionalHeader.DataDirectory[1].Size) return true;

	//process modules
	LPSTR ModuleName = nullptr;
	while ((ModuleName = (LPSTR)RVA_VA(ImportDesc->Name, NT_Header, LocalImg)))
	{
		//get module base
		PVOID RemoteModBase = Test::GetUserModuleBase(Process, ModuleName);
		if (!RemoteModBase) return false;

		//zeroing import module name
		MemZero(ModuleName, strlen(ModuleName));

		//process entries
		PIMAGE_THUNK_DATA IHData = (PIMAGE_THUNK_DATA)RVA_VA(ImportDesc->FirstThunk, NT_Header, LocalImg);
		while (IHData->u1.AddressOfData)
		{
			//only resolve by name (ordinal not support)
			if (IHData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				return false;

			else
			{
				//get import descriptor
				IMAGE_IMPORT_BY_NAME* IBN = (PIMAGE_IMPORT_BY_NAME)RVA_VA(IHData->u1.AddressOfData, NT_Header, LocalImg);
				IHData->u1.Function = (ULONG64)GetProcAdress(RemoteModBase, IBN->Name);

				//resolve failed
				if (!IHData->u1.Function)
					return false;

				//DbgPrint("[FACE] %s --> 0x%p\n", )

				//zero set import function name
				MemZero(IBN->Name, strlen(IBN->Name));
			}

			//goto next entry
			IHData++;
		}

		//goto next entry
		ImportDesc++;
	} 
	
	return true;
}

//bool __forceinline MapResolver(loaderdata LoaderData)
//{
//	PVOID pRemoteLoaderData = AllocateMemory(sizeof(loaderdata));
//	WriteArr((ULONG64)pRemoteLoaderData, &LoaderData, sizeof(loaderdata));
//
//	// Debug
//	loaderdata* pLoaderData = (loaderdata*)pRemoteLoaderData;
//	
//	PUCHAR Executor = DummyExecutor;
//	//parse dll
//	PIMAGE_NT_HEADERS DllNtHeader = NT_HEADER(Executor);
//
//	ULONG Offset = 0x5C9 + 2; // Skip [mov rax,]
//
//	//PUCHAR patt = FindSignature(Executor, sizeof(DummyExecutor), (PBYTE) "x48\xB8\x37\x13\xDE\xC0\xAD\xDE\xCE\xFA");
//	ULONG64 PathPlace = (ULONG64)Executor + Offset;
//
//	*(DWORD64*)PathPlace = (DWORD64)pRemoteLoaderData;
//
//	PVOID pRemoteBase = AllocateMemory(DllNtHeader->OptionalHeader.SizeOfImage);
//
//	if (!pRemoteBase)
//		return false;
//
//	RelocateImage(DllNtHeader, pRemoteBase, Executor);
//	SectionsMgr(DllNtHeader, pRemoteBase, Executor);
//
//	PVOID EPoint = (PVOID)((ULONG64)pRemoteBase + DllNtHeader->OptionalHeader.AddressOfEntryPoint);
//
//	PVOID ImportEntry = GetImportTableEntry(Globals::m_LastProcess, "user32.dll", "NtUserGetForegroundWindow");
//
//	if (!ImportEntry)
//		return false;
//
//	*reinterpret_cast<PVOID*>(&x64Executor[3]) = ImportEntry;
//	*reinterpret_cast<PVOID*>(&x64Executor[46]) = (PVOID)EPoint;
//
//	ReadArr((uintptr_t)ImportEntry, &x64Executor[13], sizeof(PVOID));
//	unsigned char* pMappedShellcode = reinterpret_cast<unsigned char*>(AllocateMemory(sizeof(x64Executor)));
//
//	if (!pMappedShellcode)
//		return false;
//
//	WriteArr((uintptr_t)pMappedShellcode, x64Executor, sizeof(x64Executor));
//
//	ULONG OldProtect = ProtectMemory((uintptr_t)ImportEntry, sizeof(ImportEntry), PAGE_READWRITE);
//
//	auto ShellCodeEntry = pMappedShellcode + 1;
//
//	WriteArr((uintptr_t)ImportEntry, &ShellCodeEntry, sizeof(ShellCodeEntry));
//
//	for (PVOID importValue = nullptr;; Sleep(1))
//	{
//		ReadArr((uintptr_t)ImportEntry, &importValue, sizeof(importValue));
//
//		if (importValue != ShellCodeEntry)
//		{
//			break;
//		}
//	}
//
//	ProtectMemory((uintptr_t)ImportEntry, sizeof(ImportEntry), PAGE_READONLY);
//
//	for (unsigned char status = 0;; Sleep(1))
//	{
//		ReadArr((uintptr_t)pMappedShellcode, &status, sizeof(status));
//
//		if (status)
//		{
//			break;
//		}
//	}
//
//	//FreeMemory(pMappedShellcode, 0);
//
//}