# PHOOK - A C++ x64 Hooking Library for Windows

PHOOK is a lightweight, feature-rich hooking library for Windows x64 applications, written in C++. It provides a simple and robust API for creating and managing various types of hooks and patches.

## ✨ Features

  * **Multiple Hook Types**: Supports relative jumps (`E9`), vtable swaps, relative calls (`E8`), and direct byte patching.
  * **Automatic Hook Sizing**: Intelligently determines the required instruction size for hooks, removing guesswork.
  * **Trampoline Generation**: Automatically generates trampolines to preserve the original function's behavior.
  * **Stealth Options**: Includes features to enhance stealth, such as unlinking the module from the LDR, zeroing out the PE header, and protecting memory regions from being queried.
  * **Thread Safety**: Freezes threads during hook application/removal to ensure atomicity and prevent race conditions (this can be disabled).
  * **Simple API**: Designed with a clean and straightforward interface for easy integration.

-----

## 🚀 Getting Started

To use PHOOK, you must first initialize the library, then create and manage your hooks. When you are done, you must clean up by unhooking, destroying the hooks, and uninitializing the library.

### 1\. Initialization

Initialize the library once, preferably when your DLL is attached. Pass your module's `HMODULE` and any desired flags.

```cpp
#include "phook.h"

// Your DLL's module handle
extern HMODULE g_hModule; 

void InitializeMyHooks()
{
    // Initialize with the VQ protection flag
    PHRET r = PHOOK::INITIALIZE(g_hModule, PHOOK_FLAG_VQ_PROT);
    if (r != PHR_OK)
    {
        // Handle initialization failure
        return;
    }
    //... create and enable hooks
}
```

### 2\. The Detour Function

A standard hook redirects code execution from a `TargetFunction` to your custom detour function (`HK_TARGET_FUNCTION`). To call the original function from within your detour, you use the trampoline pointer (`OG_TARGET_FUNCTION`).

```cpp
// 1. Define a function pointer type that matches the target function's signature.
typedef int (__cdecl* fpTargetFunction)(int arg1, bool arg2);

// 2. Create a global or member pointer of that type to hold the trampoline address.
fpTargetFunction OG_TARGET_FUNCTION = nullptr;

// 3. Write your detour function with the same signature.
int HK_TARGET_FUNCTION(int arg1, bool arg2)
{
    // You can execute code *before* the original function.
    printf("Hook called! arg1 = %d\n", arg1);
    
    // Call the original function via the trampoline.
    int original_return_value = OG_TARGET_FUNCTION(arg1, arg2);
    
    // You can execute code *after* the original function, and even modify its return value.
    return original_return_value + 5;
}
```

### 3\. Creating and Enabling Hooks

You can create various types of hooks using `PHOOK::CREATE_HOOK` and enable them with `PHOOK::HOOK`.

#### Relative Jump (`PHT_REL_JMP`)

This is the most common hook type. It overwrites the beginning of the target function with a `JMP` instruction that redirects to your detour.

> ⚠️ **Important**: `PHT_REL_JMP` hooks are designed to be placed at the **very beginning of a function**. Placing a relative jump hook in the middle of a function will corrupt its logic, destroy the stack frame, and almost certainly crash the application. This should only be attempted by advanced users who can manually manage the execution context (e.g., by writing the detour in assembly).

**Note**: For the `ullHookSize` parameter, it's recommended to pass `0`. This allows the library's built-in disassembler (hde64) to automatically determine the correct number of bytes to overwrite without cutting an instruction in half.

```cpp
// TargetFunction is the function we want to hook.
PHRET r = PHOOK::CREATE_HOOK(TargetFunction, HK_TARGET_FUNCTION, (void**)&OG_TARGET_FUNCTION, 0, PHT_REL_JMP);
if (r == PHR_OK)
{
    // Now enable the hook to make it active.
    PHOOK::HOOK(TargetFunction);
}
```

#### VTable Hook (`PHT_VTABLE`)

This replaces a function pointer in a virtual function table (vftable) or any other function pointer array.

```cpp
// Assume 'm_vftableDog' is a pointer to the vtable and we know the offset.
void** m_hookDog_Bark = (void**)((uintptr_t)m_vftableDog + VFTABLE_BARK_OFFSET);

PHRET r = PHOOK::CREATE_HOOK(m_hookDog_Bark, HK_DOG_BARK, (void**)&OG_DOG_BARK, 0, PHT_VTABLE);
if (r == PHR_OK)
{
    PHOOK::HOOK(m_hookDog_Bark);
}
```

#### Call Hook (`PHT_CALL`)

This replaces a specific `call` instruction (`E8`) with a call to your detour instead. This is useful for intercepting a function call from a single, specific location in the code.

```cpp
// Address of the 'call' instruction we want to intercept.
void* pCallInstruction = (void*)0x140001234; 

PHRET r = PHOOK::CREATE_HOOK(pCallInstruction, HK_TARGET_FUNCTION, (void**)&OG_TARGET_FUNCTION, 0, PHT_CALL);
if (r == PHR_OK)
{
    PHOOK::HOOK(pCallInstruction);
}
```

#### Byte Patch (`PHT_PATCH`)

This method overwrites a sequence of bytes at the target address. No trampoline is created, so the `ppTrampoline` argument should be `nullptr`.

```cpp
// Patch TargetFunction to simply return 'false' (xor al, al; ret)
const char* patchBytes = "\x30\xc0\xc3";
size_t patchSize = 3;

PHRET r = PHOOK::CREATE_HOOK(TargetFunction, (void*)patchBytes, nullptr, patchSize, PHT_PATCH);
if (r == PHR_OK)
{
    PHOOK::HOOK(TargetFunction);
}
```

### 4\. Enabling/Disabling Multiple Hooks

You can enable or disable multiple hooks in a single, thread-safe operation.

> 💡 **Pro-Tip**: By default (`PHOOK_FLAG_NO_FREEZE` is not set), PHOOK freezes all threads in the process during hook enabling/disabling to ensure stability. For hooks that will always be active, **it is highly recommended to enable them all at once** using the vector overload (`PHOOK::HOOK(vec_pvoid)`). This performs a single freeze/thaw operation for all hooks, which is much more efficient than the repeated freeze/thaw cycles caused by enabling them one by one.

```cpp
std::vector<void*> hooks_to_enable;

// Create hook 1
PHOOK::CREATE_HOOK(TargetFunction1, HK_FUNC_1, (void**)&OG_FUNC_1, 0);
hooks_to_enable.push_back(TargetFunction1);

// Create hook 2
PHOOK::CREATE_HOOK(TargetFunction2, HK_FUNC_2, (void**)&OG_FUNC_2, 0);
hooks_to_enable.push_back(TargetFunction2);

// Enable all created hooks at once for max efficiency
PHRET r = PHOOK::HOOK(hooks_to_enable);
if (r != PHR_OK)
{
    // One or more hooks failed to enable. 
    // It's recommended to enable them individually to debug.
}

// You can also disable them all at once
PHOOK::UNHOOK(hooks_to_enable);
```

### 5\. Cleanup

When your DLL is detaching or you no longer need the hooks, you must clean up properly and in the correct order.

```cpp
void CleanupMyHooks()
{
    // 1. Disable all active hooks.
    PHOOK::UNHOOK();
    
    // 2. Destroy all created hooks and free associated memory.
    PHOOK::DESTROY_HOOK();
    
    // 3. Uninitialize the library.
    PHOOK::UNINITIALIZE();
}
```

-----

## 📖 API Reference

### Initialization Flags (`uint64_t`)

Flags passed to `PHOOK::INITIALIZE`. Can be combined using the `|` operator.

  * `PHOOK_FLAG_UNLINKED_MODULE`: Unlinks the module from the Process Environment Block's LDR lists.
  * `PHOOK_FLAG_REMOVE_PE_HEADER`: Zeroes out the PE header of your module in memory.
  * `PHOOK_FLAG_VQ_PROT`: Installs a hook on `NtQueryVirtualMemory` to protect the library's memory regions from being easily discovered.
  * `PHOOK_FLAG_NO_FREEZE`: Disables the Suspend/Resume thread logic that normally runs when hooks are enabled or disabled.
  * `PHOOK_STEALTH_MODE`: A convenient macro that combines the `UNLINKED_MODULE`, `REMOVE_PE_HEADER`, and `VQ_PROT` flags.

### Hook Types (`PHTYPE`)

  * `PHT_REL_JMP`: Standard detour using a 5-byte relative jump (`JMP`).
  * `PHT_VTABLE`: Swaps a function pointer in memory (e.g., in a vtable).
  * `PHT_CALL`: Replaces a 5-byte relative call (`CALL`) instruction.
  * `PHT_PATCH`: Overwrites a specified number of bytes at the target address.

### Functions

  * `PHRET INITIALIZE(HMODULE hModule, uint64_t flags)`: Initializes the library.
  * `PHRET UNINITIALIZE()`: Uninitializes the library and frees resources.
  * `PHRET CREATE_HOOK(void* pTarget, void* pHook, void** ppTrampoline, size_t ullHookSize, PHTYPE type)`: Creates a hook object but does not enable it.
  * `PHRET DESTROY_HOOK()`: Destroys all created hooks.
  * `PHRET DESTROY_HOOK(void* pTarget)`: Destroys a specific hook.
  * `PHRET HOOK(void* pTarget)`: Enables a previously created hook.
  * `PHRET HOOK(vec_pvoid targets)`: Enables multiple hooks.
  * `PHRET UNHOOK()`: Disables all active hooks.
  * `PHRET UNHOOK(void* pTarget)`: Disables a specific hook.
  * `PHRET UNHOOK(vec_pvoid targets)`: Disables multiple hooks.
  * `PHRET IS_HOOKED(void* pTarget)`: Checks if a specific target is currently hooked.
  * `vec_mem MEM_BLOCKS()`: Returns a vector of memory blocks allocated by the library.

### Return Codes (`PHRET`)

All functions return a `PHRET` enum value to indicate success or failure. Always check the return value.

  * `PHR_OK`: The operation was successful.
  * `PHR_INVALID_HOOK_SIZE`: The specified hook size is too small (minimum is 5 bytes for jmp/call).
  * `PHR_HOOK_NOT_FOUND`: The specified hook could not be found for an operation (e.g., destroy, enable).
  * `PHR_ALLOC_FAILED`: A memory allocation failed.
  * *... and other error codes as defined in the header.*
  
  
## This README was generated by AI