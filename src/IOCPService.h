#pragma once
#include "IOCPHandler.h"
#include "Sync.h"
#include <list>

class IOCPService
{
public:
	IOCPService();
	~IOCPService();

	bool iocpSvcInit(IOCPHandler* pHandler, int numOfIoThreads = 0);
	bool iocpSvcFree();
	bool iocpSvcRegisterSocket(SOCKET s);
	bool iocpSvcPostCompletion(SOCKET s, DWORD dwTransferred, LPOVERLAPPED pol);

protected:
	void DispatchCompletionThread();
	static unsigned int WINAPI _workerThread(void* pThis)
	{
		(reinterpret_cast<IOCPService*>(pThis))->DispatchCompletionThread();
		return 0;
	}

private:
	HANDLE m_hIOCP = nullptr;
	HANDLE m_hStopEvnet = nullptr;
	AutoHandle   m_workThread;
	// iocp handler ptr
	IOCPHandler* m_pHandler = nullptr;
	std::list<HANDLE> IoThreadHandleList;
};

