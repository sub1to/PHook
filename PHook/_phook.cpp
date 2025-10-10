#include "_phook.h"
#include "hook.h"
#include "mem.h"
#include "stealth.h"

#include <TlHelp32.h>
#include <map>
#include <queue>

namespace _phook
{
	typedef std::deque<DWORD>			dequeDW;

	//initiated
	bool				m_initialized	= false;

	//vector of created hooks
	hookMap*			m_hookMap		= nullptr;

	//deque of thread ids
	dequeDW*			m_threads		= nullptr;

	// should freeze threads on (un)hook
	bool				m_freeze		= true;


	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTION DEFINITIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTION DEFINITIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTION DEFINITIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTION DEFINITIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTION DEFINITIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTION DEFINITIONS /////////////////////////////////////////////////////////////////////////////////////////////////

	size_t		freeze_threads			();
	size_t		resume_threads			();

	bool		resolve_rel				(void* pRel, size_t size, void* pStart, void* pEnd);


	//////////////////////////////////////////////////////////////////////////////////////////// PUBLIC FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PUBLIC FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PUBLIC FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PUBLIC FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PUBLIC FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PUBLIC FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////


	/*
		Initialize PHook

		@param
			flags			uint64_t	Init Flags

		@return		PHRET
			PHR_OK					Initialized
			PHR_ALREADY_INITIALIZED	Not initialized
			PHR_ALLOC_FAILED		Memory allocation failed
	*/
	__declspec(noinline) PHRET	initialize(HMODULE hModule, uint64_t flags)
	{
		PHRET				ret;

		ret		= PHR_INIT_FAILED;

		if(m_initialized)
		{
			ret	= PHR_ALREADY_INITIALIZED;
			goto LABEL_RETURN;
		}

		m_hookMap			= new hookMap;
		mem::m_memBlocks	= new mem::vecMB;
		m_threads			= new dequeDW;

		m_initialized		= true;
		m_freeze			= !(flags & PHOOK_FLAG_NO_FREEZE);

		//need to set m_initialized to true first, because stealth::initialize can create hooks
		stealth::initialize(hModule, flags);

		ret		= PHR_OK;
		
	LABEL_RETURN:
		return ret;
	}

	/*
		Uninitialize PHook

		@return		PHRET
			PHR_OK					Uninitialized
			PHR_NOT_INITIALIZED		Not initialized
			PHR_UNDESTROYED_HOOKS	There are still undestroyed hooks
	*/
	__declspec(noinline) PHRET	uninitialize()
	{
		PHRET	ret;

		ret		= PHR_OK;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		if(m_hookMap->size() > 0)
		{
			ret		= PHR_UNDESTROYED_HOOKS;
			goto LABEL_RETURN;
		}

		stealth::uninitialize();

		//free all the memory blocks
		for(mem::vecMB::iterator it = mem::m_memBlocks->begin(); it != mem::m_memBlocks->end(); ++it)
		{	
			VirtualFree((*it)->start(), 0, MEM_RELEASE);
			delete *it;
		}

		delete m_hookMap;
		delete mem::m_memBlocks;
		delete m_threads;

		m_initialized	= false;

	LABEL_RETURN:
		return ret;
	}

	/*
		Create a hook

		@param
			pTarget			void*		The target function
			pHook			void*		The detour function
			ppTrampoline	void**		Pointer to the trampoline pointer
			ullHookSize		size_t		Number of bytes that will be replaced
			type			PHTYPE		The hook type
			cfg				vec_phcfg	Vector of additional configurations

		@return		PHRET
			PHR_OK					Hook created
			PHR_NOT_INITIALIZED		Not initialized
			PHR_INVALID_HOOK_SIZE	Invalid hook size (minimum depends on the hook type)
			PHR_ALREADY_EXISTS		Hook already exists
	*/
	PHRET	create_hook(void* pTarget, void* pHook, void** ppTrampoline, size_t ullHookSize, PHTYPE type)
	{
		PHRET	ret;
		IPHook*	pPHook;

		ret		= PHR_OK;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		if(m_hookMap->count(pTarget))
		{
			ret		= PHR_ALREADY_EXISTS;
			goto LABEL_RETURN;
		}

		switch(type)
		{
			case PHT_REL_JMP:
				if(ullHookSize < 5 && ullHookSize > 0)
				{
					ret		= PHR_INVALID_HOOK_SIZE;
					goto LABEL_RETURN;
				}
				pPHook	= (IPHook*) new CPHookRelJmp(pTarget, pHook, ullHookSize);
				break;

			case PHT_VTABLE:
				pPHook	= (IPHook*) new CPHookVTable(pTarget, pHook);
				break;

			case PHT_CALL:
				if(ullHookSize < 5 && ullHookSize > 0)
				{
					ret		= PHR_INVALID_HOOK_SIZE;
					goto LABEL_RETURN;
				}
				pPHook	= (IPHook*)	new CPHookCall(pTarget, pHook, ullHookSize);
				break;

			case PHT_PATCH:
				pPHook	= (IPHook*) new CPHookPatch(pTarget, pHook, ullHookSize);
		}

		m_hookMap->emplace(pTarget, pPHook);
		if(ppTrampoline){
			*ppTrampoline	= pPHook->trampoline();
		}

	LABEL_RETURN:
		return ret;
	}

	/*
		Destroy all hooks

		@return	PHRET
			PHR_OK				Hooked
			PHR_NOT_INITIALIZED	Not initialized
			PHR_STILL_HOOKED	One or more functions are still hooked
	*/
	PHRET	destroy_hook()
	{
		PHRET	ret;

		ret		= PHR_OK;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		for(hookMap::iterator it = m_hookMap->begin(); it != m_hookMap->end(); ++it)
		{
			if(it->second->enabled())
			{
				ret		= PHR_STILL_HOOKED;
				goto LABEL_RETURN;
			}
		}

		for(hookMap::iterator it = m_hookMap->begin(); it != m_hookMap->end(); ++it)
			delete	it->second;

		m_hookMap->clear();

	LABEL_RETURN:
		return ret;
	}

	/*
		Destroy a hook

		@param
			pTarget		void*		The target function
			
		@return	PHRET
			PHR_OK				Hooked
			PHR_NOT_INITIALIZED	Not initialized
			PHR_HOOK_NOT_FOUND	Hook not found
			PHR_STILL_HOOKED	Function is still hooked
	*/
	PHRET	destroy_hook(void* pTarget)
	{
		hookMap::iterator	it;
		PHRET				ret;

		ret		= PHR_OK;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		it	= m_hookMap->find(pTarget);

		if(it == m_hookMap->end())
		{
			ret		=  PHR_HOOK_NOT_FOUND;
			goto LABEL_RETURN;
		}

		if(it->second->enabled())
		{
			ret		=  PHR_STILL_HOOKED;
			goto LABEL_RETURN;
		}

		delete it->second;
		m_hookMap->erase(it);

	LABEL_RETURN:
		return ret;
	}

	/*
		Enable a hook

		@param
			pTarget		void*		The target function

		@return	PHRET
			PHR_OK				Hooked
			PHR_NOT_INITIALIZED	Not initialized
			PHR_HOOK_NOT_FOUND	Hook not found
	*/
	PHRET	hook(void* pTarget)
	{
		hookMap::iterator	it;
		PHRET				ret;

		ret		= PHR_OK;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		it	= m_hookMap->find(pTarget);

		if(it == m_hookMap->end())
		{
			ret		=  PHR_HOOK_NOT_FOUND;
			goto LABEL_RETURN;
		}

		if(it->second->enabled())
			goto LABEL_RETURN;

		if(m_freeze){
			freeze_threads();
			it->second->enable();
			resume_threads();
		} else {
			it->second->enable();
		}

	LABEL_RETURN:
		return ret;
	}

	/*
		Enable hooks

		@param
			targets		vec_pvoid		the target functions

		@return	PHRET
			PHR_OK				Hooked
			PHR_NOT_INITIALIZED	Not initialized
			PHR_HOOK_NOT_FOUND	Hook not found
	*/
	PHRET	hook(vec_pvoid targets)
	{
		hookMap::iterator	it;
		PHRET				ret;
		bool				frozen;

		ret		= PHR_OK;
		frozen	= false;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		for(vec_pvoid::iterator tar = targets.begin(); tar != targets.end(); ++tar){
			it	= m_hookMap->find(*tar);

			if(it == m_hookMap->end())
			{
				ret		=  PHR_HOOK_NOT_FOUND;
				continue;
			}

			if(it->second->enabled()){
				continue;
			}

			if(m_freeze && !frozen){
				frozen	= true;
				freeze_threads();
			}

			it->second->enable();
		}

		if(frozen){
			resume_threads();
		}

	LABEL_RETURN:
		return ret;
	}

	/*
		Unhook All

		@return		PHRET
			PHR_OK				All unhooked
			PHR_NOT_INITIALIZED	Not initialized
	*/
	PHRET	unhook()
	{
		PHRET	ret;
		ret		= PHR_OK;

		if(m_freeze)
			freeze_threads();

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		for(hookMap::iterator it = m_hookMap->begin(); it != m_hookMap->end(); ++it)
			it->second->disable();

	LABEL_RETURN:
		if(m_freeze)
			resume_threads();
		return ret;
	}

	/*
		Disable a hook

		@param
			pTarget		void*		The target function

		@return		PHRET
			PHR_OK				Hook found; Unhooked
			PHR_HOOK_NOT_FOUND	Hook not found
			PHR_NOT_INITIALIZED	Not initialized
	*/
	PHRET	unhook(void* pTarget)
	{
		hookMap::iterator	it;
		PHRET				ret;

		ret		= PHR_OK;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		it	= m_hookMap->find(pTarget);

		if(it == m_hookMap->end())
		{
			ret		=  PHR_HOOK_NOT_FOUND;
			goto LABEL_RETURN;
		}

		if(!it->second->enabled())
			goto LABEL_RETURN;

		if(m_freeze){
			freeze_threads();
			it->second->disable();
			resume_threads();
		} else {
			it->second->disable();
		}

	LABEL_RETURN:
		return ret;
	}

	/*
		Disable hooks

		@param
			targets		vec_pvoid		the target functions

		@return	PHRET
			PHR_OK				Hook found; Unhooked
			PHR_HOOK_NOT_FOUND	Hook not found
			PHR_NOT_INITIALIZED	Not initialized
	*/
	PHRET	unhook(vec_pvoid targets)
	{
		hookMap::iterator	it;
		PHRET				ret;
		bool				frozen;

		ret		= PHR_OK;
		frozen	= false;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		for(vec_pvoid::iterator tar = targets.begin(); tar != targets.end(); ++tar){
			it	= m_hookMap->find(*tar);

			if(it == m_hookMap->end())
			{
				ret		=  PHR_HOOK_NOT_FOUND;
				continue;
			}

			if(!it->second->enabled()){
				continue;
			}

			if(!frozen){
				frozen	= true;
				freeze_threads();
			}

			it->second->disable();
		}

		if(frozen){
			resume_threads();
		}

	LABEL_RETURN:
		return ret;
	}

	/*
		@return		PHRET
			PHR_OK				Hook found; target is hooked
			PHR_NOT_HOOKED		Hook found; target is unhooked
			PHR_HOOK_NOT_FOUND	Hook not found
			PHR_NOT_INITIALIZED	Not initialized
	*/
	PHRET	is_hooked(void* pTarget)
	{
		hookMap::iterator	it;
		PHRET				ret;

		ret		= PHR_OK;

		if(!m_initialized)
		{
			ret		= PHR_NOT_INITIALIZED;
			goto LABEL_RETURN;
		}

		it	= m_hookMap->find(pTarget);

		if(it == m_hookMap->end())
		{
			ret		=  PHR_HOOK_NOT_FOUND;
			goto LABEL_RETURN;
		}

		if(!it->second->enabled())
		{
			ret		=  PHR_NOT_HOOKED;
			goto LABEL_RETURN;
		}

	LABEL_RETURN:
		return ret;
	}

	vec_mem mem_blocks()
	{
		vec_mem	vec;

		for(mem::vecMB::iterator it = mem::m_memBlocks->begin(); it != mem::m_memBlocks->end(); ++it)
			vec.push_back((IMemBlock*) *it);

		return vec;
	}




	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////// PRIVATE FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////

	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms686852(v=vs.85).aspx
	size_t	freeze_threads()
	{
		size_t			ret;
		HANDLE			hThreadSnap		= INVALID_HANDLE_VALUE;
		THREADENTRY32	te32;
		DWORD			ulCurrentProcessId;
		DWORD			ulCurrentThreadId;
		
		ret					= 0;

		if(m_threads == nullptr)
			goto LABEL_RETURN;

		hThreadSnap			= CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		ulCurrentProcessId	= GetCurrentProcessId();
		ulCurrentThreadId	= GetCurrentThreadId();

		if(hThreadSnap == INVALID_HANDLE_VALUE)
			goto LABEL_RETURN;

		te32.dwSize	= sizeof(te32);

		if(!Thread32First(hThreadSnap, &te32))
			goto LABEL_RETURN;

		do
		{
			HANDLE	hThread;

			if(te32.th32OwnerProcessID != ulCurrentProcessId || te32.th32ThreadID == ulCurrentThreadId)
				continue;

			hThread		= OpenThread(THREAD_SUSPEND_RESUME, 0, te32.th32ThreadID);

			if(hThread == nullptr)
				continue;

			m_threads->push_back(te32.th32ThreadID);
			SuspendThread(hThread);
			CloseHandle(hThread);

			++ret;

		} while(Thread32Next(hThreadSnap, &te32));

	LABEL_RETURN:
		if(hThreadSnap != INVALID_HANDLE_VALUE)
			CloseHandle(hThreadSnap);
		return ret;
	}

	size_t	resume_threads()
	{
		size_t	ret;

		ret		= 0;

		if(m_threads == nullptr)
			goto LABEL_RETURN;

		for(dequeDW::iterator it = m_threads->begin(); it != m_threads->end(); ++it)
		{
			HANDLE	hThread;

			hThread		= OpenThread(THREAD_SUSPEND_RESUME, 0, *it);

			if(hThread == nullptr)
				continue;

			ResumeThread(hThread);
			CloseHandle(hThread);

			++ret;
		}

		m_threads->clear();

	LABEL_RETURN:
		return ret;
	}

	bool resolve_rel(void* pRel, size_t size, void* pStart, void* pEnd)
	{
		bool		ret;
		ptrdiff_t	llDelta;
		size_t		ullByteSize;

		ret			= false;
		ullByteSize	= 0;
		llDelta		= (char*) pEnd - (char*) pStart;

		for(int64_t i = (llDelta < 0 ? -llDelta : llDelta) << 1; i != 0; ++ullByteSize, i >>= 8);

		if(size > 8 || ullByteSize > size){
			goto LABEL_RETURN;
		}

		memcpy_s(pRel, size, &llDelta, size);
		ret		= true;

	LABEL_RETURN:
		return ret;
	}
};