#ifndef MEM_H
#define MEM_H

class CMemBlock : IMemBlock
{
public:
	CMemBlock(void* start, size_t size);
	~CMemBlock();

	void*	allocate(size_t size);

	virtual	void*	start();
	virtual	void*	end();
			size_t	free();
	
protected:
	void*		m_pStart;
	void*		m_pEnd;
	char*		m_pFree;
};

namespace mem
{
	typedef std::vector<CMemBlock*>		vecMB;

	//vector of virtual memory blocks
	extern vecMB*		m_memBlocks;

	CMemBlock*	alloc_block				(void* pTarget);
	void*		alloc					(size_t size, void* pTarget);
	void*		virtual_alloc_near		(void* pTarget, size_t size, DWORD allocType, DWORD protect, size_t maxDelta = ALLOC_MAX_DELTA);
};

#endif //MEM_H