#pragma comment(linker, "/MERGE:.rdata=INIT")
#pragma comment(linker, "/MERGE:.pdata=INIT")

#define _FI __forceinline
#define VadRootOffset 0x7d8

#include <ntifs.h>
#include <intrin.h>
#include "xor.h"
namespace Globals
{
	ULONG64 m_KernelBase = NULL;
	PULONG64 m_pPspCidTable = nullptr;
	ULONG64 m_ExDestroyHandleFn = NULL;
	PEPROCESS m_LastProcess = nullptr;
}

#include "sdk.h"
#include "Vad.h"
#include "utils.h"

#include "bytes.h"
#include "inject.h"
