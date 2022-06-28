#pragma once
class MemPool
{
	void MemPoolsInit();
	void MemPoolsFree();

	void* MpAlloc(unsigned int size, int align = 0);
	void MpFree(void* buffer, unsigned int maxPoolSize = 0);
};

