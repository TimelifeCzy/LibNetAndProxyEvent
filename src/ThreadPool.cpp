#include "ThreadPool.h"
#include <process.h>

ThreadPool::ThreadPool()
{
	m_pJobSource = NULL;
	m_stopEvent.Attach(CreateEvent(NULL, TRUE, FALSE, NULL));
}

ThreadPool::~ThreadPool()
{
	free();
}

void ThreadPool::threadProc()
{
	HANDLE handles[] = { m_jobAvailableEvent, m_stopEvent };

	m_pJobSource->threadStarted();

	do {
		DWORD res = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

		if (res == (WAIT_OBJECT_0 + 1))
			break;

		m_pJobSource->execute();
	} while (1);

	m_pJobSource->threadStopped();
}

bool ThreadPool::init(int threadCount, ThreadJobSource* pJobSource)
{
	if (!pJobSource)
		return false;
	ResetEvent(m_stopEvent);

	m_pJobSource = pJobSource;

	if (threadCount <= 0)
	{
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);

		threadCount = sysinfo.dwNumberOfProcessors;
		if (threadCount == 0)
		{
			threadCount = 1;
		}
	}

	int idx = 0; HANDLE hThread;
	for (idx = 0; idx < threadCount; ++idx)
	{
		hThread = (HANDLE)_beginthreadex(NULL, 0, _threadProc, (LPVOID)this, 0, NULL);
		if (hThread)
			m_threads.push_back(hThread);
	}
	if (m_threads.empty())
		return false;
	return true;
}

bool ThreadPool::free()
{
	SetEvent(m_stopEvent);
	for (tThreads::iterator it = m_threads.begin();
		it != m_threads.end();
		it++)
	{
		WaitForSingleObject(*it, INFINITE);
		CloseHandle(*it);
	}

	m_threads.clear();
	return true;
}

void ThreadPool::jobAvailable()
{
	SetEvent(m_jobAvailableEvent);
}