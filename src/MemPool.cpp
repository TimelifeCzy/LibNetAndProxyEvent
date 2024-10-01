#include "MemPool.h"
#include <mutex>

typedef struct _MEM_BUFFER
{
	struct _MEM_BUFFER* pNext;
	unsigned int size;
	char buffer[1];
} MEM_BUFFER, * PMEM_BUFFER;

typedef struct _MEM_POOL
{
	unsigned int buffer_size;
	unsigned int nBuffers;
	PMEM_BUFFER pFreeBuffers;
} MEM_POOL, * PMEM_POOL;

static int nPools = 0;
static std::mutex mem_pools_lock;
static MEM_POOL mem_pools[100];

void MemPool::MemPoolsInit()
{
	nPools = 0;
}

void MemPool::MemPoolsFree()
{

}

void* MemPool::MpAlloc(unsigned int size, int align)
{
	if (size == 0)
		return nullptr;

	if (align > 0)
		size = ((size / align) + 1) * align;


	PMEM_BUFFER pMemBuffer = nullptr;
	int idx = 0;

	mem_pools_lock.lock();
	
	for (idx = 0; idx < nPools; ++idx)
	{
		if (mem_pools[idx].buffer_size != size)
			continue;
		if (mem_pools[idx].pFreeBuffers)
		{
			pMemBuffer = mem_pools[idx].pFreeBuffers;
			mem_pools[idx].pFreeBuffers = pMemBuffer->pNext;
			mem_pools->nBuffers--;
			mem_pools_lock.unlock();
			return pMemBuffer->buffer;
		}
		else
			break;
	}

	mem_pools_lock.unlock();

	pMemBuffer = (PMEM_BUFFER)new char(sizeof(MEM_BUFFER) + size - 1);
	if (!pMemBuffer)
	{
		return NULL;
	}
	pMemBuffer->size = size;
	return pMemBuffer->buffer;
}

void MemPool::MpFree(void* buffer, unsigned int maxPoolSize)
{
	PMEM_BUFFER pMemBuffer = nullptr;
	int idx = 0;
	if (!buffer)
		return;
	pMemBuffer = (PMEM_BUFFER)((char*)buffer - (char*)(&((PMEM_BUFFER)0)->buffer));
}