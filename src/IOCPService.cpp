#include "IOCPService.h"
#include <process.h>

IOCPService::IOCPService() : m_hIOCP(INVALID_HANDLE_VALUE), m_pHandler(NULL)
{
	m_hStopEvnet = CreateEvent(NULL, TRUE, FALSE, NULL);
}

IOCPService::~IOCPService()
{
	if (m_hStopEvnet != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hStopEvnet);
		m_hStopEvnet = INVALID_HANDLE_VALUE;
	}
}

void IOCPService::DispatchCompletionThread()
{
	if (INVALID_HANDLE_VALUE == m_hIOCP)
		return;
	DWORD dwTransferred; ULONG_PTR cKey; OVERLAPPED* pOverlapped = nullptr;
	do {

		if (GetQueuedCompletionStatus(m_hIOCP, &dwTransferred, &cKey, &pOverlapped, 500))
		{
			m_pHandler->onComplete((SOCKET)cKey, dwTransferred, pOverlapped, 0);
		}
		else
		{
			DWORD err = GetLastError();
			if (err != WAIT_TIMEOUT)
			{
				m_pHandler->onComplete((SOCKET)cKey, dwTransferred, pOverlapped, err);
			}
		}
		// waitFotSing Stop
		if (WaitForSingleObject(m_hStopEvnet, 0) == WAIT_OBJECT_0)
			break;
	} while (1);
}

bool IOCPService::iocpSvcInit(IOCPHandler* pHandler, int numOfIoThreads)
{
	m_pHandler = pHandler;
	// create io completionport
	if (INVALID_HANDLE_VALUE != m_hIOCP)
		return false;
	m_hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
	if (INVALID_HANDLE_VALUE == m_hIOCP)
		return false;

	// set m_hStopEvnet
	ResetEvent(m_hStopEvnet);

	// start thread number
	if (0 == numOfIoThreads)
		numOfIoThreads = 1;
	
	int idx = 0;
	for (idx = 0; idx < numOfIoThreads; ++idx)
	{
		HANDLE hThread = (HANDLE)_beginthreadex(0, 0, _workerThread, (LPVOID)this, 0, NULL);
		if (hThread)
			IoThreadHandleList.push_back(hThread);
	}
	if (IoThreadHandleList.empty())
	{
		CloseHandle(m_hIOCP);
		return false;
	}

	return true;
}

bool IOCPService::iocpSvcFree()
{
	SetEvent(m_hStopEvnet);
	size_t workingThreadCount = IoThreadHandleList.size();
	std::list<HANDLE>::iterator iter;
	while (workingThreadCount > 0)
	{
		workingThreadCount = 0;
		for (iter = IoThreadHandleList.begin(); iter != IoThreadHandleList.end(); iter++)
		{
			DWORD exitCode;
			if (GetExitCodeThread(*iter, &exitCode) && exitCode == STILL_ACTIVE)
				workingThreadCount++;
		}
	}
	for (iter = IoThreadHandleList.begin(); iter != IoThreadHandleList.end(); iter++)
	{
		CloseHandle(*iter);
	}
	IoThreadHandleList.clear();

	if (m_hIOCP != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hIOCP);
		m_hIOCP = INVALID_HANDLE_VALUE;
	}
	return true;
}

bool IOCPService::iocpSvcRegisterSocket(SOCKET s)
{
	if (!CreateIoCompletionPort((HANDLE)s, m_hIOCP, (ULONG_PTR)s, 1))
		return false;
	return true;
}

bool IOCPService::iocpSvcPostCompletion(SOCKET s, DWORD dwTransferred, LPOVERLAPPED pol)
{
	return PostQueuedCompletionStatus(m_hIOCP, dwTransferred, (ULONG_PTR)s, pol) ? true : false;
}