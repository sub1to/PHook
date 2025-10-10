#include "_phook.h"
#include "mem.h"

//////////////////////////////////////////////////////////////////////////////////////////// CMemBlock CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CMemBlock CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CMemBlock CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CMemBlock CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CMemBlock CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////// CMemBlock CLASS FUNCTIONS /////////////////////////////////////////////////////////////////////////////////////////////////

CMemBlock::CMemBlock(void* start, size_t size) :
	m_pStart(start),
	m_pFree((char*) start),
	m_pEnd((char*) start + size)
{

}

CMemBlock::~CMemBlock()
{

}

void*	CMemBlock::allocate(size_t size)
{
	void*	ret;

	ret		= nullptr;

	if((m_pFree + size) > m_pEnd)
		goto LABEL_RETURN;

	ret			= m_pFree;
	m_pFree		+= size;

LABEL_RETURN:
	return ret;
}

void*	CMemBlock::start()
{
	return m_pStart;
}

void*	CMemBlock::end()
{
	return m_pEnd;
}

size_t	CMemBlock::free()
{
	return (uint64_t) m_pEnd - (uint64_t) m_pFree;
}


namespace mem
{
	vecMB*		m_memBlocks		= nullptr;

	/*
		Allocate new virtual memory block near pTarget

		@param
			pTarget			void*		Pointer to address in memory the allocation should be close to

		@return				CMemBlock*	A pointer to the CMemBlock object of the block
	*/
	CMemBlock*	alloc_block(void* pTarget)
	{
		CMemBlock* pBlock;

		pBlock		= nullptr;
		pTarget		= virtual_alloc_near(pTarget, ALLOC_BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(pTarget == nullptr){
			MessageBoxA(nullptr, "Allocation failed", "Fatal Error", MB_OK | MB_ICONERROR);
			goto LABEL_RETURN;
		}
			
		pBlock	= new CMemBlock(pTarget, ALLOC_BLOCK_SIZE);
		m_memBlocks->push_back(pBlock);

	LABEL_RETURN:
		return pBlock;
	}

	/*
		Allocate memory near pTarget

		@param
			size			size_t		Allocation size
			pTarget			void*		Pointer to address in memory the allocation should be close to

		@return				void*		Pointer to allocated memory (or nullptr if failed)
	*/
	void*		alloc(size_t size, void* pTarget)
	{
		void*		ret;
		char*		pMin;
		char*		pMax;
		CMemBlock*	pBlock;

		ret		= nullptr;
		pMin	= (char*) pTarget - ALLOC_MAX_DELTA;
		pMax	= (char*) pTarget + ALLOC_MAX_DELTA;

		for(vecMB::iterator it = m_memBlocks->begin(); it != m_memBlocks->end(); ++it)
		{
			void*	pStart	= (*it)->start();
			if(pStart > pMin && pStart < pMax && (*it)->free() >= size)
			{
				pBlock	= *it;
				goto LABEL_RETURN;
			}
		}

		pBlock	= alloc_block(pTarget);

	LABEL_RETURN:
		if(pBlock != nullptr)
			ret		= pBlock->allocate(size);
		return ret;
	}

	void*	virtual_alloc_near(void* pTarget, size_t size, DWORD allocType, DWORD protect, size_t maxDelta)
	{
		MEMORY_BASIC_INFORMATION	mbi;
		SYSTEM_INFO					si;
		void*						ret;
		uint64_t					ullStart;
		uint64_t					ullLimit;

		GetSystemInfo(&si);
	
		ret			= 0;
		ullStart	= (uint64_t) pTarget;
		ullLimit	= ullStart + ALLOC_MAX_DELTA;
		ullStart	-= ullStart % si.dwAllocationGranularity;
		ullStart	+= si.dwAllocationGranularity;

		while(ullStart < ullLimit)
		{
			if(sizeof(mbi) != VirtualQuery((void*) ullStart, &mbi, sizeof(mbi))){
				ullStart	+= si.dwAllocationGranularity;
				continue;
			}

			if(mbi.State == MEM_FREE && (ullStart + size) < ((uint64_t) mbi.BaseAddress + mbi.RegionSize))
			{
				ret    = VirtualAlloc((void*) ullStart, size, allocType, protect);
				if(ret)
					goto LABEL_RETURN;
			}

			ullStart	= (uint64_t) mbi.BaseAddress + mbi.RegionSize;
			ullStart	+= si.dwAllocationGranularity - 1;
			ullStart	-= ullStart % si.dwAllocationGranularity;
		}

		ullStart	= (uint64_t) pTarget;
		ullLimit	= ullStart;
		ullStart	= ullStart - ALLOC_MAX_DELTA;
		ullStart	-= ullStart % si.dwAllocationGranularity;
		ullStart	+= si.dwAllocationGranularity;

		while(ullStart < ullLimit)
		{
			if(sizeof(mbi) != VirtualQuery((void*) ullStart, &mbi, sizeof(mbi))){
				ullStart	+= si.dwAllocationGranularity;
				continue;
			}

			if(mbi.State == MEM_FREE && (ullStart + size) < ((uint64_t) mbi.BaseAddress + mbi.RegionSize))
			{
				ret    = VirtualAlloc((void*) ullStart, size, allocType, protect);
				if(ret)
					goto LABEL_RETURN;
			}

			ullStart	= (uint64_t) mbi.BaseAddress + mbi.RegionSize;
			ullStart	+= si.dwAllocationGranularity - 1;
			ullStart	-= ullStart % si.dwAllocationGranularity;
		}

	LABEL_RETURN:
		return ret;
	}
};
