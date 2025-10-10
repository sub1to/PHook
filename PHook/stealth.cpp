#include "_phook.h"
#include "stealth.h"
#include "mem.h"
#include "hook.h"

#include <intrin.h>

namespace stealth
{
	//the payload module
	HMODULE				m_hModule			= nullptr;
	size_t				m_ullModuleSize		= 0;

	//removed pe headers & unlinked modules	
	PUNLINKED_MODULE	m_unlinkedModule	= nullptr;
	PERASED_PEHEADER	m_erasedPeHeader	= nullptr;

	IPHook*				m_vqHook			= nullptr;

	//WinAPI Trampolines
	fpVirtualQuery			OG_VIRTUAL_QUERY			= nullptr;
	fpVirtualQueryEx		OG_VIRTUAL_QUERY_EX			= nullptr;
	fpNtQueryVirtualMemory	OG_NT_QUERY_VIRTUAL_MEMORY	= nullptr;
	fpVirtualProtect		OG_VIRTUAL_PROTECT			= nullptr;

	//////////////////////////////////////////////////////////////////////////////////////////// FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////

	__declspec(noinline) bool initialize(HMODULE hModule, uint64_t flags)
	{
		bool				ret;
		PIMAGE_DOS_HEADER	pDosHeader;
		PIMAGE_NT_HEADERS	pNTHeader;

		ret			= false;
		m_hModule	= hModule;
		pDosHeader	= (PIMAGE_DOS_HEADER) hModule;
		pNTHeader	= (PIMAGE_NT_HEADERS) ((PBYTE)pDosHeader + (DWORD) pDosHeader->e_lfanew);

		if(pNTHeader->Signature != IMAGE_NT_SIGNATURE || !pNTHeader->OptionalHeader.SizeOfHeaders)
			goto LABEL_RETURN;

		if(flags & PHOOK_FLAG_VQ_PROT)
		{
			//Virtual Query & Virtual Protect bypasses
			BYTE* ptr;

			ptr												= (BYTE*) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
			m_vqHook										= (IPHook*) new CPHookRelJmp(ptr, stealth::HK_NT_QUERY_VIRTUAL_MEMORY, 0);
			*(void**) &stealth::OG_NT_QUERY_VIRTUAL_MEMORY	= m_vqHook->trampoline();
			m_vqHook->enable();
		}

		if(flags & PHOOK_FLAG_UNLINKED_MODULE)
		{
			m_unlinkedModule	= new UNLINKED_MODULE;
			unlink_module_from_peb();
		}

		if(flags & PHOOK_FLAG_REMOVE_PE_HEADER)
		{
			m_erasedPeHeader	= new ERASED_PEHEADER;
			remove_pe_header();
		}

		ret		= true;

	LABEL_RETURN:
		return ret;
	}

	__declspec(noinline) bool uninitialize()
	{
		if(m_erasedPeHeader != nullptr)
		{
			restore_pe_header();
			delete m_erasedPeHeader;
			m_erasedPeHeader	= nullptr;
		}

		if(m_unlinkedModule != nullptr)
		{
			relink_module_to_peb();
			delete m_unlinkedModule;
			m_unlinkedModule	= nullptr;
		}

		if(m_vqHook != nullptr)
		{
			m_vqHook->disable();
			delete m_vqHook;
			m_vqHook		= nullptr;
		}
		
		m_hModule		= 0;
		m_ullModuleSize	= 0;	

		return true;
	}

	__declspec(noinline) bool relink_module_to_peb()
	{
		bool				ret;

		ret	= false;

		if(m_unlinkedModule->hModule == 0)
			goto LABEL_RETURN;

		RELINK(m_unlinkedModule->Entry->InLoadOrderModuleList, m_unlinkedModule->RealInLoadOrderLinks);
		RELINK(m_unlinkedModule->Entry->InMemoryOrderModuleList, m_unlinkedModule->RealInInitializationOrderLinks);
		RELINK(m_unlinkedModule->Entry->InInitializationOrderModuleList, m_unlinkedModule->RealInMemoryOrderLinks);
		RELINK(m_unlinkedModule->Entry->HashTableEntry, m_unlinkedModule->RealHashTableEntry);

		m_unlinkedModule->Entry->BaseAddress	= m_hModule;
		m_unlinkedModule->hModule				= 0;
		ret										= true;

	LABEL_RETURN:
		return ret;
	}
 
	__declspec(noinline) bool unlink_module_from_peb()
	{
		bool				ret;
		BYTE*				_teb;
		PPEB_LDR			pLdrData;
		PLIST_ENTRY			pUserModuleHead;
		PLIST_ENTRY			pUserModule;

		ret	= false;
 
		if(m_unlinkedModule->hModule != 0)
			goto LABEL_RETURN;
 
		_teb			= (BYTE*)__readgsqword(0x30);
		pLdrData		= (PPEB_LDR) (*(uint64_t*)((*(uint64_t*)(_teb + 0x60)) + 0x18));
		pUserModuleHead = 
		pUserModule		= (PLIST_ENTRY) &(pLdrData->InLoadOrderModuleList);

		for(pUserModule = pUserModule->Flink; pUserModule != pUserModuleHead; pUserModule = pUserModule->Flink)
		{
			PLDR_MODULE ldrModule;

			ldrModule = (PLDR_MODULE) pUserModule;

			if(ldrModule->BaseAddress == m_hModule)
			{
				m_unlinkedModule->hModule							= m_hModule;
				m_unlinkedModule->RealInLoadOrderLinks				= ldrModule->InLoadOrderModuleList.Blink->Flink;
				m_unlinkedModule->RealInInitializationOrderLinks	= ldrModule->InMemoryOrderModuleList.Blink->Flink;
				m_unlinkedModule->RealInMemoryOrderLinks			= ldrModule->InInitializationOrderModuleList.Blink->Flink;
				m_unlinkedModule->RealHashTableEntry				= ldrModule->HashTableEntry.Blink->Flink;
				m_unlinkedModule->Entry								= ldrModule;

				UNLINK(ldrModule->InLoadOrderModuleList);
				UNLINK(ldrModule->InMemoryOrderModuleList);
				UNLINK(ldrModule->InInitializationOrderModuleList);
				UNLINK(ldrModule->HashTableEntry);

				memset(ldrModule->FullDllName.Buffer, 0, ldrModule->FullDllName.Length);
				ldrModule->FullDllName.Length	= 0;
				memset(ldrModule->BaseDllName.Buffer, 0, ldrModule->BaseDllName.Length);
				ldrModule->BaseDllName.Length	= 0;
				ldrModule->BaseAddress			= nullptr;
				ldrModule->EntryPoint			= nullptr;

				break;
			}
		}
		ret	= true;

	LABEL_RETURN:
		return ret;

	}

	__declspec(noinline) bool remove_pe_header()
	{
		bool				ret;
		PIMAGE_DOS_HEADER	pDosHeader;
		PIMAGE_NT_HEADERS	pNTHeader;
		DWORD				dwProt;
		size_t				ullSize;
		BYTE*				pBuffer;

		ret			= false;

		if(m_erasedPeHeader->hModule != 0)
			goto LABEL_RETURN;

		pDosHeader	= (PIMAGE_DOS_HEADER) m_hModule;
		pNTHeader	= (PIMAGE_NT_HEADERS) ((PBYTE)pDosHeader + (DWORD) pDosHeader->e_lfanew);

		if(pNTHeader->Signature != IMAGE_NT_SIGNATURE || !pNTHeader->OptionalHeader.SizeOfHeaders)
			goto LABEL_RETURN;

		ullSize	= pNTHeader->OptionalHeader.SizeOfHeaders;
		pBuffer	= (BYTE*) VirtualAlloc(nullptr, ullSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		VirtualProtect((void*)m_hModule, ullSize, PAGE_EXECUTE_READWRITE, &dwProt);

		m_erasedPeHeader->hModule	= m_hModule;
		m_erasedPeHeader->pBuffer	= pBuffer;
		m_erasedPeHeader->size		= ullSize;
		m_erasedPeHeader->ulProtect	= dwProt;

		memcpy_s(pBuffer, ullSize, m_hModule, ullSize);
		VirtualProtect(pBuffer, ullSize, PAGE_NOACCESS, &dwProt);
		memset((void*)m_hModule, 0, ullSize);
		VirtualProtect((void*)m_hModule, ullSize, PAGE_NOACCESS, &dwProt);

		ret	= true;

	LABEL_RETURN:
		return ret;
	}

	__declspec(noinline) bool restore_pe_header()
	{
		bool				ret;
		DWORD				dwProt;

		ret	= false;
 
		if(m_erasedPeHeader->hModule == 0)
			goto LABEL_RETURN;

		VirtualProtect(m_erasedPeHeader->pBuffer, m_erasedPeHeader->size, PAGE_READWRITE, &dwProt);
		VirtualProtect((void*) m_erasedPeHeader->hModule, m_erasedPeHeader->size, PAGE_EXECUTE_READWRITE, &dwProt);	
		memcpy_s(m_erasedPeHeader->hModule, m_erasedPeHeader->size, m_erasedPeHeader->pBuffer, m_erasedPeHeader->size);
		VirtualProtect((void*) m_erasedPeHeader->hModule, m_erasedPeHeader->size, m_erasedPeHeader->ulProtect, &dwProt);

		//delete[] m_erasedPeHeader->pBuffer;
		VirtualFree(m_erasedPeHeader->pBuffer, 0, MEM_RELEASE);

		m_erasedPeHeader->hModule	= 0;
		ret							= true;

	LABEL_RETURN:
		return ret;
	}

	//////////////////////////////////////////////////////////////////////////////////////////// WinAPI Hooks /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// WinAPI Hooks /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// WinAPI Hooks /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// WinAPI Hooks /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// WinAPI Hooks /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// WinAPI Hooks /////////////////////////////////////////////////////////////////////////////////////////////////

	/*
		__kernel_entry NTSYSCALLAPI NTSTATUS NtQueryVirtualMemory(
		  HANDLE                   ProcessHandle,
		  PVOID                    BaseAddress,
		  MEMORY_INFORMATION_CLASS MemoryInformationClass,
		  PVOID                    MemoryInformation,
		  SIZE_T                   MemoryInformationLength,
		  PSIZE_T                  ReturnLength
		);

		ntdll.NtQueryVirtualMemory - 4C 8B D1              - mov r10,rcx
		ntdll.NtQueryVirtualMemory+3 - B8 23 00 00 00           - mov eax,00000023 { 35 }
	*/
	size_t HK_NT_QUERY_VIRTUAL_MEMORY(HANDLE hProcess, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
	{
		vec_mem vec;

		if(GetProcessId(hProcess) != GetCurrentProcessId())
			goto LABEL_RETURN;

		if(BaseAddress >= m_hModule && BaseAddress < ((BYTE*) m_hModule + m_ullModuleSize))
		{
			return 0xC0000022;	// STATUS_ACCESS_DENIED https://msdn.microsoft.com/en-us/library/cc704588.aspx
		}

		for(_phook::hookMap::iterator it = _phook::m_hookMap->begin(); it != _phook::m_hookMap->end(); ++it)
		{
			IPHook*	pHook	= it->second;
			BYTE*	pTarget	= reinterpret_cast<BYTE*>(pHook->target());

			if(pHook->enabled() && BaseAddress >= pTarget && BaseAddress < (pTarget + pHook->size())){
				BYTE*	main_base = (BYTE*) GetModuleHandleA(nullptr);
				//log?
				break;
			}
		}

		for(mem::vecMB::iterator it = mem::m_memBlocks->begin(); it != mem::m_memBlocks->end(); ++it)
		{
			if(BaseAddress >= (*it)->start() && BaseAddress < (*it)->end()){
				return 0xC0000022;
			}
		}

	LABEL_RETURN:	
		return OG_NT_QUERY_VIRTUAL_MEMORY(hProcess, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	}
};

