#include "_phook.h"
#include "hook.h"
#include "mem.h"

#include "hde64\hde64.h"

/*
//CONST EXPRESSIONS
*/
constexpr BYTE		LONGJMP_OPCODE[]	= { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };	//jmp qword ptr [rip]
constexpr size_t	LONGJMP_SIZE		= 0xE;										//size of opcode + address

/*
0:  50                      push   rax
1:  48 b8 e0 86 f3 67 f6    movabs rax,0x7ff667f386e0
8:  7f 00 00
b:  48 87 04 24             xchg   QWORD PTR [rsp],rax
f:  c3                      ret 
*/
constexpr BYTE		LONGRET_OPCODE[]		= { 0x50, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x04, 0x24, 0xC3 };
constexpr BYTE		LONGRET_ADDR_OFFSET		= 3;

constexpr BYTE		JMP_OPCODE[]		= { 0xE9, 0x00, 0x00, 0x00, 0x00 };			//jmp 0x0
constexpr BYTE		CALL_OPCODE[]		= { 0xE8, 0x00, 0x00, 0x00, 0x00 };			//call 0x0

void create_basic_trampline(void** ppTrampOut, size_t size, void* pTarget)
{
	BYTE*	pByte;

	*ppTrampOut	= mem::alloc(size + get_array_size(JMP_OPCODE), pTarget);
	pByte		= *(BYTE**) ppTrampOut + size;

	memcpy_s(*ppTrampOut, size, pTarget, size);

	memcpy_s((void*) pByte, get_array_size(JMP_OPCODE), JMP_OPCODE, get_array_size(JMP_OPCODE));
	_phook::resolve_rel(pByte + 1, sizeof(int32_t), pByte + get_array_size(JMP_OPCODE), (BYTE*) pTarget + size);
}

void create_longjump(void** ppLJOut, void* pDetour, void* pTarget)
{
	*ppLJOut	= mem::alloc(LONGJMP_SIZE, pTarget);

	memcpy_s(*ppLJOut, get_array_size(LONGJMP_OPCODE), LONGJMP_OPCODE, get_array_size(LONGJMP_OPCODE));
	memcpy_s(*(BYTE**)ppLJOut + get_array_size(LONGJMP_OPCODE), sizeof(uint64_t), pDetour, sizeof(uint64_t));
}

void create_longret(void** ppLJOut, void* pDetour, void* pTarget)
{
	*ppLJOut	= mem::alloc(get_array_size(LONGRET_OPCODE), pTarget);

	memcpy_s(*ppLJOut, get_array_size(LONGRET_OPCODE), LONGRET_OPCODE, get_array_size(LONGRET_OPCODE));
	memcpy_s(*(BYTE**)ppLJOut + LONGRET_ADDR_OFFSET, sizeof(uint64_t), pDetour, sizeof(uint64_t));
}

//////////////////////////////////////////////////////////////////////////////////////////// CPHook CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHook CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHook CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHook CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHook CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHook CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////

CPHook::CPHook() :
	m_bEnabled(false)
{
	//
}

void*	CPHook::target()
{
	return m_pTarget;
}

void*	CPHook::trampoline()
{
	return m_pTraBuf;
}

void*	CPHook::hook()
{
	return m_pHook;
}

size_t	CPHook::size()
{
	return m_ullHkSize;
}

bool	CPHook::enable()
{
	bool	ret;
	DWORD	ulProt;

	ret		= false;

	if(m_bEnabled)
		goto LABEL_RETURN;

	VirtualProtect(m_pTarget, m_ullHkSize, PAGE_EXECUTE_READWRITE, &ulProt);
	memcpy_s(m_pTarget, m_ullHkSize, m_pHkBuf, m_ullHkSize);
	VirtualProtect(m_pTarget, m_ullHkSize, ulProt, &ulProt);

	m_bEnabled	= true;
	ret			= true;

LABEL_RETURN:
	return ret;
}

bool	CPHook::disable()
{
	bool	ret;
	DWORD	ulProt;

	ret		= false;

	if(!m_bEnabled)
		goto LABEL_RETURN;

	VirtualProtect(m_pTarget, m_ullHkSize, PAGE_EXECUTE_READWRITE, &ulProt);
	memcpy_s(m_pTarget, m_ullHkSize, m_pOrigBuf, m_ullHkSize);
	VirtualProtect(m_pTarget, m_ullHkSize, ulProt, &ulProt);

	m_bEnabled	= false;
	ret			= true;

LABEL_RETURN:
	return ret;
}

bool	CPHook::enabled()
{
	return m_bEnabled;
}


//////////////////////////////////////////////////////////////////////////////////////////// CPHookRelJmp CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookRelJmp CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookRelJmp CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookRelJmp CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookRelJmp CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookRelJmp CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////

CPHookRelJmp::CPHookRelJmp(void* pTarget, void* pHook, size_t size)
{
	if(size == 0)
	{
		hde64s		ins;

		while(size < 5)
		{
			memset(&ins, 0, sizeof(ins));
			hde64_disasm((BYTE*) pTarget + size, &ins);
        
			size        += ins.len;
		}
	}

	//set member variables
	m_pTarget	= pTarget;
	m_pHook		= pHook;
	m_ullHkSize	= size;

	//create tampoline
	create_basic_trampline((void**) &m_pTraBuf, size, pTarget);
	
	//set up the long jump
	//create_longjump((void**) &m_pLJBuf, &pHook, pTarget);
	create_longret((void**) &m_pLJBuf, &pHook, pTarget);

	//set up the hook
	m_pHkBuf	= new BYTE[size];

	memcpy_s((void*) m_pHkBuf, get_array_size(JMP_OPCODE), JMP_OPCODE, get_array_size(JMP_OPCODE));
	_phook::resolve_rel(m_pHkBuf + 1, sizeof(int32_t), (BYTE*) pTarget + get_array_size(JMP_OPCODE), m_pLJBuf);

	m_pOrigBuf	= new BYTE[size];
	memcpy_s(m_pOrigBuf, size, pTarget, size);

	for(size_t i = get_array_size(JMP_OPCODE); i < size; ++i)
		m_pHkBuf[i]		= 0x90;

	for(size_t i = 0; i < size;){
		hde64s		ins;
		size_t		rel_size;
		size_t		rel_offset;
		BYTE*		pTarget;

		rel_size	= 0;
		rel_offset	= 0;
		pTarget		= (BYTE*) m_pTarget + i;

		memset(&ins, 0, sizeof(ins));
		hde64_disasm((BYTE*) m_pTarget + i, &ins);
        
		if(ins.flags & F_RELATIVE && ins.flags & F_IMM32 && ins.len >= 5){

			rel_size	= sizeof(int32_t);

			for(size_t j = ins.len - rel_size; j > 0; --j){
				if(*(uint32_t*) (pTarget + j) != ins.imm.imm32)
					continue;

				rel_offset	= j;
				break;
			}
		}
		else if(ins.flags & F_DISP32){
		
		}

		if(rel_size > 0 && rel_offset > 0){
			_phook::resolve_rel(	m_pTraBuf + i + rel_offset, 
									rel_size,
									m_pTraBuf + i + ins.len,
									(BYTE*) m_pTarget + i + ins.len + *reinterpret_cast<int32_t*>(&ins.imm.imm32)	);
		}

		i	+= ins.len;
	}
}

CPHookRelJmp::~CPHookRelJmp()
{
	delete[] m_pHkBuf;
	delete[] m_pOrigBuf;
}

//////////////////////////////////////////////////////////////////////////////////////////// CPHookVTable CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookVTable CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookVTable CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookVTable CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookVTable CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookVTable CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////

CPHookVTable::CPHookVTable(void* pTarget, void* pHook)
{
	m_pTarget	= pTarget;
	m_pHook		= pHook;
	m_ullHkSize	= sizeof(void*);

	//set up the hook
	m_pOrigBuf	= new BYTE[sizeof(void*)];
	m_pHkBuf	= new BYTE[sizeof(void*)];

	*(void**) m_pOrigBuf	= *(void**) pTarget;
	*(void**) m_pHkBuf		= pHook;
}

CPHookVTable::~CPHookVTable()
{
	delete[] m_pOrigBuf;
	delete[] m_pHkBuf;
}

void*	CPHookVTable::trampoline()
{
	return *(void**) m_pTarget;
}

//////////////////////////////////////////////////////////////////////////////////////////// CPHookCall CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookCall CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookCall CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookCall CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookCall CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookCall CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////

CPHookCall::CPHookCall(void* pTarget, void* pHook, size_t size)
{
	if(size == 0)
	{
		hde64s		ins;

		while(size < 5)
		{
			memset(&ins, 0, sizeof(ins));
			hde64_disasm((BYTE*) pTarget + size, &ins);
        
			size        += ins.len;
		}
	}

	//set member variables
	m_pTarget	= pTarget;
	m_pHook		= pHook;
	m_ullHkSize	= size;

	if(*(BYTE*) pTarget == 0xE8){	//hijack an existing e8 instruction.. requires a different trampoline
		m_pTraBuf		= (BYTE*) mem::alloc(1 + get_array_size(CALL_OPCODE), pTarget);
		memcpy_s(m_pTraBuf, get_array_size(CALL_OPCODE), pTarget, 5);
		m_pTraBuf[0]	= 0xE9;
	} else {
		// I hope you know what you're doing... In most cases this will crash, because it pushes an extra
		// return address to the stack when entering the hook.
		create_basic_trampline((void**) &m_pTraBuf, size, pTarget);
	}
	
	//set up the long jump
	create_longret((void**) &m_pLJBuf, &pHook, pTarget);

	//set up the hook
	m_pHkBuf	= new BYTE[size];

	memcpy_s((void*) m_pHkBuf, get_array_size(CALL_OPCODE), CALL_OPCODE, get_array_size(CALL_OPCODE));
	_phook::resolve_rel(m_pHkBuf + 1, sizeof(int32_t), (BYTE*) pTarget + get_array_size(CALL_OPCODE), m_pLJBuf);

	m_pOrigBuf	= new BYTE[size];
	memcpy_s(m_pOrigBuf, size, pTarget, size);

	for(size_t i = get_array_size(CALL_OPCODE); i < size; ++i)
		m_pHkBuf[i]		= 0x90;

	for(size_t i = 0; i < size;){
		hde64s		ins;
		size_t		rel_size;
		size_t		rel_offset;
		BYTE*		pTarget;

		rel_size	= 0;
		rel_offset	= 0;
		pTarget		= (BYTE*) m_pTarget + i;

		memset(&ins, 0, sizeof(ins));
		hde64_disasm((BYTE*) m_pTarget + i, &ins);
        
		if(ins.flags & F_RELATIVE && ins.flags & F_IMM32 && ins.len >= 5){

			rel_size	= sizeof(int32_t);

			for(size_t j = ins.len - rel_size; j > 0; --j){
				if(*(uint32_t*) (pTarget + j) != ins.imm.imm32)
					continue;

				rel_offset	= j;
				break;
			}
		}
		else if(ins.flags & F_DISP32){
		
		}

		if(rel_size > 0 && rel_offset > 0){
			_phook::resolve_rel(	m_pTraBuf + i + rel_offset, 
									rel_size,
									m_pTraBuf + i + ins.len,
									(BYTE*) m_pTarget + i + ins.len + *reinterpret_cast<int32_t*>(&ins.imm.imm32)	);
		}

		i	+= ins.len;
	}
}

CPHookCall::~CPHookCall()
{
	delete[] m_pHkBuf;
	delete[] m_pOrigBuf;
}

//////////////////////////////////////////////////////////////////////////////////////////// CPHookPatch CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookPatch CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookPatch CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookPatch CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookPatch CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CPHookPatch CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////


CPHookPatch::CPHookPatch(void* pTarget, void* pHook, size_t size)
{
	//set member variables
	m_pTarget	= pTarget;
	m_pHook		= pHook;
	m_ullHkSize	= size;

	//set up the patch
	m_pHkBuf	= new BYTE[size];
	m_pOrigBuf	= new BYTE[size];

	memcpy_s(m_pHkBuf, size, pHook, size);
	memcpy_s(m_pOrigBuf, size, pTarget, size);
}

CPHookPatch::~CPHookPatch()
{
	delete[] m_pHkBuf;
	delete[] m_pOrigBuf;
}

