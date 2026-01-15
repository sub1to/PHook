/*
	Copyright 2025-9999 sub1to

	This file is part of PHook

	PHook is free software; See LICENSE.MD or https://opensource.org/license/mit
*/

#ifndef STEALTH_H
#define STEATLH_H

#define UNLINK(x)					\
	(x).Flink->Blink = (x).Blink;	\
	(x).Blink->Flink = (x).Flink;
 
#define RELINK(x, real)			\
	(x).Flink->Blink = (real);	\
	(x).Blink->Flink = (real);	\
	(real)->Blink = (x).Blink;	\
	(real)->Flink = (x).Flink;

typedef struct UNICODE_STRING
{
	uint16_t	Length;
	uint16_t	MaxLength;
	WCHAR*		Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct PEB_LDR
{
	uint32_t		Length;
	uint8_t			Initialized;
	void*			SsHandle;
	LIST_ENTRY		InLoadOrderModuleList;
	LIST_ENTRY		InMemoryOrderModuleList;
	LIST_ENTRY		InInitializationOrderModuleList;
} PEB_LDR, *PPEB_LDR;

typedef struct LDR_MODULE
{
	LIST_ENTRY		InLoadOrderModuleList;
	LIST_ENTRY		InMemoryOrderModuleList;
	LIST_ENTRY		InInitializationOrderModuleList;
	void*			BaseAddress;
	void*			EntryPoint;
	uint32_t		SizeOfImage;
	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;
	uint32_t		Flags;
	int16_t			LoadCount;
	int16_t			TlsIndex;
	LIST_ENTRY		HashTableEntry;
	int32_t			TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;
 

typedef struct _UNLINKED_MODULE
{
	HMODULE		hModule	= 0;
	PLIST_ENTRY	RealInLoadOrderLinks;
	PLIST_ENTRY	RealInMemoryOrderLinks;
	PLIST_ENTRY	RealInInitializationOrderLinks;
	PLIST_ENTRY	RealHashTableEntry;
	PLDR_MODULE	Entry; 
} UNLINKED_MODULE, *PUNLINKED_MODULE;

typedef struct _ERASED_PEHEADER
{
	HMODULE		hModule = 0;
	BYTE*		pBuffer;
	size_t		size;
	DWORD		ulProtect;
} ERASED_PEHEADER, *PERASED_PEHEADER;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;


typedef size_t		(__cdecl*	fpVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, size_t dwLength);
typedef size_t		(__cdecl*	fpVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, size_t dwLength);
typedef NTSTATUS	(__cdecl*	fpNtQueryVirtualMemory)(HANDLE hProcess, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef BOOL		(__cdecl*	fpVirtualProtect)(LPCVOID lpAddress, size_t dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

namespace stealth
{
	//the payload module
	extern HMODULE				m_hModule;
	extern size_t				m_ullModuleSize;

	//removed pe headers & unlinked modules	
	extern PUNLINKED_MODULE	m_unlinkedModule;
	extern PERASED_PEHEADER	m_erasedPeHeader;

	//WinAPI Trampolines
	extern fpVirtualQuery			OG_VIRTUAL_QUERY;
	extern fpVirtualQueryEx		OG_VIRTUAL_QUERY_EX;
	extern fpNtQueryVirtualMemory	OG_NT_QUERY_VIRTUAL_MEMORY;
	extern fpVirtualProtect		OG_VIRTUAL_PROTECT;

	bool		initialize(HMODULE hModule, uint64_t flags);
	bool		uninitialize();

	size_t		HK_NT_QUERY_VIRTUAL_MEMORY(HANDLE hProcess, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

	bool		relink_module_to_peb	();
	bool		unlink_module_from_peb	();
	bool		remove_pe_header		();
	bool		restore_pe_header		();
};

#endif //STEALTH_H

