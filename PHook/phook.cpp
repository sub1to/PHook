/*
	Copyright 2025-9999 sub1to

	This file is part of PHook

	PHook is free software; See LICENSE.MD or https://opensource.org/license/mit
*/

#include "phook.h"
#include "_phook.h"

//////////////////////////////////////////////////////////////////////////////////////////// PHOOK NAMESPACE /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// PHOOK NAMESPACE /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// PHOOK NAMESPACE /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// PHOOK NAMESPACE /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// PHOOK NAMESPACE /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// PHOOK NAMESPACE /////////////////////////////////////////////////////////////////////////////////////////////////
namespace PHOOK
{
	//"crit sec" value for spinlock
	volatile long		m_critSec		= 0;

	/*
		Enter the PHook spinlock

		@return		void
	*/
	void	enter_spinlock()
	{
		for(size_t i = 0; _InterlockedExchange(&m_critSec, 1) != 0; ++i)
		{
			if(i < PHOOK_SPINCOUNT)
				continue;
			Sleep(1);
		}
	}

	/*
		Exit the PHook spinlock

		@return		void
	*/
	void	exit_spinlock()
	{
		_InterlockedExchange(&m_critSec, 0);
	}

	PHRET	INITIALIZE(HMODULE hModule, uint64_t flags)
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::initialize(hModule, flags);

		exit_spinlock();

		return ret;
	}

	/*
		Uninitialize PHook

		@return		PHRET
	*/
	PHRET	UNINITIALIZE()
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::uninitialize();

		exit_spinlock();

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
	*/
	PHRET	CREATE_HOOK(void* pTarget, void* pHook, void** ppTrampoline, size_t ullHookSize, PHTYPE type)
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::create_hook(pTarget, pHook, ppTrampoline, ullHookSize, type);

		exit_spinlock();

		return ret;
	}

	/*
		Destroy all hooks

		@return	PHRET
	*/
	PHRET	DESTROY_HOOK()
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::destroy_hook();

		exit_spinlock();

		return ret;
	}

	/*
		Destroy a hook

		@param
			pTarget		void*		The target function
			
		@return	PHRET
	*/
	PHRET	DESTROY_HOOK(void* pTarget)
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::destroy_hook(pTarget);

		exit_spinlock();

		return ret;
	}

	/*
		Enable a hook

		@param
			pTarget		void*		The target function

		@return	PHRET
	*/
	PHRET	HOOK(void* pTarget)
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::hook(pTarget);

		exit_spinlock();

		return ret;
	}

	/*
		Enable multiple hooks

		This will NOT bail if one of the hooks fails to enable

		@param
			targets		vec_pvoid	vector of targets

		@return PHRET
	*/
	PHRET	HOOK(vec_pvoid targets)
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::hook(targets);

		exit_spinlock();

		return ret;
	}

	/*
		Unhook All

		@return		PHRET
	*/
	PHRET	UNHOOK()
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::unhook();

		exit_spinlock();

		return ret;
	}

	/*
		Disable a hook

		@param
			pTarget		void*		The target function

		@return		PHRET
	*/
	PHRET	UNHOOK(void* pTarget)
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::unhook(pTarget);

		exit_spinlock();

		return ret;
	}

	/*
		Disable multiple hooks

		@param
			pTarget		void*		The target function

		@return		PHRET
	*/
	PHRET	UNHOOK(vec_pvoid targets)
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::unhook(targets);

		exit_spinlock();

		return ret;
	}

	/*
		@return		PHRET
	*/
	PHRET	IS_HOOKED(void* pTarget)
	{
		PHRET	ret;

		enter_spinlock();

		ret	= _phook::is_hooked(pTarget);

		exit_spinlock();

		return ret;
	}

	/*
		@return		vec_mem
	*/
	vec_mem	MEM_BLOCKS()
	{
		vec_mem	ret;

		enter_spinlock();

		ret	= _phook::mem_blocks();

		exit_spinlock();

		return ret;
	}
};
