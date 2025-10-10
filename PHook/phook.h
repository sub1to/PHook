#ifndef PHOOK_H
#define PHOOK_H

#include <Windows.h>
#include <vector>

/*
	Memory blocks
*/

class IMemBlock
{
public:
	virtual void*	start()		= 0;
	virtual void*	end()		= 0;
};

typedef std::vector<IMemBlock*>		vec_mem;

/*
	PHook return values
*/
enum PHRET : unsigned
{
	PHR_OK,
	PHR_ALREADY_INITIALIZED,
	PHR_NOT_INITIALIZED,
	PHR_INVALID_HOOK_SIZE,
	PHR_HOOK_NOT_FOUND,
	PHR_NOT_HOOKED,
	PHR_STILL_HOOKED,
	PHR_UNDESTROYED_HOOKS,
	PHR_ALREADY_EXISTS,
	PHR_ALLOC_FAILED,
	PHR_INIT_FAILED,
};

/*
	PHook hook types
*/
enum PHTYPE : unsigned
{
	PHT_REL_JMP,
	PHT_VTABLE,
	PHT_CALL,
	PHT_PATCH,
};

typedef std::vector<void*>		vec_pvoid;

/*
	PHook initialization flags
*/
#define PHOOK_FLAG_UNLINKED_MODULE	(1 << 0)
#define PHOOK_FLAG_REMOVE_PE_HEADER	(1 << 1)
#define PHOOK_FLAG_VQ_PROT			(1 << 2)
#define PHOOK_FLAG_NO_FREEZE		(1 << 3)

#define PHOOK_STEALTH_MODE			(PHOOK_FLAG_UNLINKED_MODULE | PHOOK_FLAG_REMOVE_PE_HEADER | PHOOK_FLAG_VQ_PROT)


namespace PHOOK
{
	/*
		Initialize PHook

		@param
			hModule			HMODULE		Pointer to your DLL (Not the HMODULE of the target you're hooking in to)
			flags			uint64_t	Init Flags

		@return		PHRET
	*/
	PHRET	INITIALIZE(HMODULE hModule, uint64_t flags = 0);

	/*
		Uninitialize PHook

		@return		PHRET
	*/
	PHRET	UNINITIALIZE();

	/*
		Create a hook

		@param
			pTarget			void*		The target function
			pHook			void*		The detour function
			ppTrampoline	void**		Pointer to the trampoline pointer
			ullHookSize		size_t		Number of bytes that will be replaced. Can be 0 (hde64 will decide the length)
			type			PHTYPE		The hook type

		@return		PHRET
	*/
	PHRET	CREATE_HOOK(void* pTarget, void* pHook, void** ppTrampoline, size_t ullHookSize = 0x5, PHTYPE type = PHT_REL_JMP);

	/*
		Destroy all hooks

		@return	PHRET
	*/
	PHRET	DESTROY_HOOK();

	/*
		Destroy a hook

		@param
			pTarget		void*		The target function
			
		@return	PHRET
	*/
	PHRET	DESTROY_HOOK(void* pTarget);

	/*
		Enable a hook

		@param
			pTarget		void*		The target function

		@return	PHRET
	*/
	PHRET	HOOK(void* pTarget);

	/*
		Enable multiple hooks

		This will NOT bail if one of the hooks fails to enable, and does not give info about which hook failed.
		If it doesn't return PHR_OK, enable them 1 by 1 and see what's going on.. tough shit..

		@param
			targets		vec_pvoid	vector of targets

		@return PHRET
	*/
	PHRET	HOOK(vec_pvoid targets);

	/*
		Unhook All

		@return		PHRET
	*/
	PHRET	UNHOOK();

	/*
		Disable a hook

		@param
			pTarget		void*		The target function

		@return		PHRET
	*/
	PHRET	UNHOOK(void* pTarget);

	/*
		Disable multiple hooks

		This will NOT bail if one of the hooks fails to enable, and does not give info about which hook failed.
		If it doesn't return PHR_OK, enable them 1 by 1 and see what's going on.. tough shit..

		@param
			targets		vec_pvoid		the target functions

		@return		PHRET
	*/
	PHRET	UNHOOK(vec_pvoid pTarget);

	/*
		@return		PHRET
	*/
	PHRET	IS_HOOKED(void* pTarget);

	/*
		@return		vec_mem
	*/
	vec_mem	MEM_BLOCKS();
};


#endif //PHOOK_H
