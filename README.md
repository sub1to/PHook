# PHook

A C++ hooking library for Windows. Originally written in 2017.

## Initialize

```cpp
PHRET phret = PHOOK::INITIALIZE(hModule, PHOOK_FLAG_VQ_PROT);
```
*Note: `hModule` of your module (dll), not the target module*

## Create Hooks

### PHT_REL_JMP

Replace instruction(s) with `E9` jmp

```cpp
PHRET phret = PHOOK::CREATE_HOOK(pTarget, HK_MY_DETOUR, (void**) &OG_MY_DETOUR, 0, PHT_REL_JMP);
```

*Note: Using size `0` makes `CREATE_HOOK` use hde64 to determine the best hook size*

### PHT_CALL

Replace an existing `E8` call instruction (or easily `ret` from your hook if you write it in ASM)

```cpp
PHRET phret = PHOOK::CREATE_HOOK(pTarget, HK_MY_DETOUR, (void**) &OG_MY_DETOUR, 5, PHT_CALL);
```

### PHT_VTABLE

Replace a function pointer in a VFT (Virtual Function Table) or the IAT (Import Address Table)

```cpp
PHRET phret = PHOOK::CREATE_HOOK(pPresent, HK_DXGI_PRESENT, (void**) &OG_DXGI_PRESENT, 0, PHT_VTABLE);
```

### PHT_PATCH

Patch a function's bytes

```cpp
// 0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
PHRET phret = PHOOK::CREATE_HOOK(pTarget, (char*) "\x0F\x1F\x44\x00\x00", nullptr, 5, PHT_PATCH);
```

## Enable Hooks

### Enable single hook
```cpp
PHRET phret = PHOOK::HOOK(pPresent);
```

### Enable multiple hooks
```cpp
PHRET phret = PHOOK::HOOK({ pIAT_CreateThread, pIAT_RegisterClassA, pIAT_D3D12CreateDevice, pIAT_CreateDXGIFactory1 });
```

## Disable Hooks

### Disable single hook
```cpp
PHRET phret = PHOOK::UNHOOK(pPresent);
```

### Disable multiple hooks
```cpp
PHRET phret = PHOOK::UNHOOK({ pIAT_CreateThread, pIAT_RegisterClassA, pIAT_D3D12CreateDevice, pIAT_CreateDXGIFactory1 });
```


## Cleanup

```cpp
PHRET phret; // feel free to check the return values
phret = PHOOK::UNHOOK(); // unhook all
phret = PHOOK::DESTROY_HOOK(); // destroy all
phret = PHOOK::UNINITIALIZE(); // free resources and shutdown
```


## Example

```cpp
typedef HANDLE      (*fpCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
fpCreateThread      OG_CREATE_THREAD    = nullptr;
HANDLE              HK_CREATE_THREAD(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    if(reinterpret_cast<BYTE*>(lpStartAddress) == SOME_THREAD_ENTRYPOINT_ADDRESS){
        return OG_CREATE_THREAD(lpThreadAttributes, dwStackSize, HK_MY_THREAD_ENRYPOINT, lpParameter, dwCreationFlags, lpThreadId);
    }

    return OG_CREATE_THREAD(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}
```

```cpp
PHRET   res;
BYTE*   pIAT_CreateThread;

res     = PHOOK::INITIALIZE(hModule, PHOOK_FLAG_VQ_PROT);

if(res != PHR_OK){
    return false;
}

// feel free to grab the get_first_iat_entry function from my mintty-liberate project
pIAT_CreateThread       = get_first_iat_entry(GetModuleHandleA(nullptr), "CreateThread");

if(pIAT_CreateThread == nullptr){
    return false;
}

res = PHOOK::CREATE_HOOK(pIAT_CreateThread, HK_CREATE_THREAD, (void**) &OG_CREATE_THREAD, 0, PHT_VTABLE);

if(res != PHR_OK){
    return false;
}

res = PHOOK::HOOK(pIAT_CreateThread);

if(res != PHR_OK){
    return false;
}

return true;
```

## License
MIT

*Note: I do not own the copyright for hde64. See copyright notice at the top of the hde64 files.*
