/*
* IOCP¥ø–È¿‡
*/
#pragma once
#include <Windows.h>

class IOCPHandler
{
public:
	virtual void onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED* pOverlapped, int error) = 0;
};

