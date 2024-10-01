#pragma once
#include "ThreadJobSource.h"
#include "Sync.h"

#include <vector>

class ThreadPool
{
public:
	ThreadPool();
	~ThreadPool();

	bool init(int threadCount, ThreadJobSource * pJobSource);
	bool free();
	void jobAvailable();

protected:
	void threadProc();

	static unsigned int WINAPI  _threadProc(void* pData)
	{
		(reinterpret_cast<ThreadPool*>(pData))->threadProc();
		return 0;
	}

private:
	ThreadJobSource* m_pJobSource;
	typedef std::vector<HANDLE> tThreads;
	tThreads		m_threads;
	AutoHandle		m_stopEvent;
	AutoEventHandle m_jobAvailableEvent;
};

