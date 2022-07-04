#pragma once
#define WIN32_LEAN_AND_MEAN

#include <ws2tcpip.h>
#include <mswsock.h>
#include <stdio.h>

#include "IOCPHandler.h"
#include "IOCPService.h"
#include "ThreadJobSource.h"
#include "ThreadPool.h"
#include "Sync.h"
#pragma comment(lib, "Ws2_32.lib")

struct TCP_PACKET
{
	TCP_PACKET()
	{
		buffer.len = 0;
		buffer.buf = NULL;
	}
	TCP_PACKET(const char* buf, int len)
	{
		if (len > 0)
		{
			buffer.buf = new char[len];
			buffer.len = len;

			if (buf)
			{
				memcpy(buffer.buf, buf, len);
			}
		}
		else
		{
			buffer.buf = NULL;
			buffer.len = 0;
		}
	}

	WSABUF& operator ()()
	{
		return buffer;
	}

	void free()
	{
		if (buffer.buf)
		{
			delete[] buffer.buf;
		}
	}

	WSABUF	buffer;
};
typedef std::vector<TCP_PACKET> tPacketList;
enum OV_TYPE
{
	OVT_ACCEPT,
	OVT_CONNECT,
	OVT_CLOSE,
	OVT_SEND,
	OVT_RECEIVE
};
struct OV_DATA
{
	OV_DATA()
	{
		memset(&ol, 0, sizeof(ol));
	}
	~OV_DATA()
	{
		for (tPacketList::iterator it = packetList.begin(); it != packetList.end(); it++)
		{
			it->free();
		}
	}

	OVERLAPPED	ol;
	LIST_ENTRY	entry;
	LIST_ENTRY	entryEventList;
	__int64		id;
	OV_TYPE		type;
	tPacketList packetList;

	SOCKET	socket;
	DWORD	dwTransferred;
	int		error;
};

class TCPProxy : public IOCPHandler, public ThreadJobSource
{
public:
	TCPProxy();
	virtual ~TCPProxy();

	bool init(unsigned short port, bool bindToLocalhost = true, int threadCount = 0);
	virtual void free();
	bool initExtensions();
	bool StartAccept(int ipFamily);
	bool startClose(SOCKET socket, __int64 id);
	bool StartConnect(SOCKET socket, sockaddr* pAddr, int addrLen, __int64 id);

protected:
	OV_DATA* newOV_DATA()
	{
		OV_DATA* pov = new OV_DATA();
		AutoLock lock(m_cs);
		return pov;
	}

	void deleteOV_DATA(OV_DATA* pov)
	{
		AutoLock lock(m_cs);
		delete pov;
	}

	// ¼Ì³Ðiocphandler
	virtual void onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED* pOverlapped, int error) override;
	// ¼Ì³ÐThread
	virtual void execute() override;
	virtual void threadStarted() override;
	virtual void threadStopped() override;
	// IocpComplet
	void onAcceptComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error);
	void onConnectComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error);
	void onSendComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error);
	void onReceiveComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error);
	void onClose(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error);
	void SetKeepAliveVals(SOCKET s);

private:
	IOCPService m_service;
	ThreadPool m_pool;
	DWORD m_timeout;

	SOCKET m_listenSocket;
	SOCKET m_acceptSocket;

	SOCKET m_listenSocket_IPv6;
	SOCKET m_acceptSocket_IPv6;

	int m_port;

	LPFN_ACCEPTEX m_pAcceptEx;
	LPFN_CONNECTEX m_pConnectEx;
	LPFN_GETACCEPTEXSOCKADDRS m_pGetAcceptExSockaddrs;

	AutoCriticalSection m_cs;

	LIST_ENTRY	m_eventList;
	AutoCriticalSection m_csEventList;
};
