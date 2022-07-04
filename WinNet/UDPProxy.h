#pragma once
#define WIN32_LEAN_AND_MEAN

#include <ws2tcpip.h>
#include <mswsock.h>
#include <stdio.h>
#include <vector>
#include <set>
#include <map>

#include "IOCPHandler.h"
#include "IOCPService.h"
#include "Sync.h"
#pragma comment(lib, "Ws2_32.lib")

#define PACKET_SIZE 65536

typedef std::vector<char> tBuffer;

enum OV_TYPE
{
	OVT_UDP_SEND,
	OVT_UDP_RECEIVE
};

struct OV_DATA
{
	OV_DATA()
	{
		memset(&ol, 0, sizeof(ol));
	}

	OVERLAPPED	ol;
	unsigned __int64 id;
	OV_TYPE		type;
	char		remoteAddress[28];
	int			remoteAddressLen;
	tBuffer		buffer;
};

typedef std::set<OV_DATA*> tOvDataSet;

struct PROXY_DATA
{
	PROXY_DATA()
	{
		udpSocket = INVALID_SOCKET;
		memset(remoteAddress, 0, sizeof(remoteAddress));
		remoteAddressLen = 0;
		udpRecvStarted = false;
	}
	~PROXY_DATA()
	{
		if (udpSocket != INVALID_SOCKET)
		{
			closesocket(udpSocket);
		}
	}

	SOCKET udpSocket;
	char remoteAddress[28];
	int remoteAddressLen;
	bool udpRecvStarted;
};

typedef std::map<unsigned __int64, PROXY_DATA*> tSocketMap;

class UDPProxyHandler
{
public:
	virtual void onUdpReceiveComplete(unsigned __int64 id, char* buf, int len, char* remoteAddress, int remoteAddressLen) = 0;
};

class UDPProxy : public IOCPHandler
{
public:
	UDPProxy();
	virtual ~UDPProxy();

	virtual void onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED* pOverlapped, int error) override;

	bool init(UDPProxyHandler* const pProxyHandler, char* proxyAddress, const int proxyAddressLen, bool bindToLocalhost = true);
	void free();
	bool startUdpReceive(SOCKET socket, unsigned __int64 id, OV_DATA* pov);
	bool udpSend(unsigned __int64 id, char* buf, int len, char* remoteAddress, int remoteAddressLen);

	bool createProxyConnection(unsigned __int64 id);
	void deleteProxyConnection(unsigned __int64 id);

protected:
	OV_DATA* newOV_DATA()
	{
		OV_DATA* pov = new OV_DATA();
		AutoLock lock(m_cs);
		m_ovDataSet.insert(pov);
		return pov;
	}

	void deleteOV_DATA(OV_DATA* pov)
	{
		AutoLock lock(m_cs);
		tOvDataSet::iterator it;
		it = m_ovDataSet.find(pov);
		if (it == m_ovDataSet.end())
			return;
		m_ovDataSet.erase(it);
		delete pov;
	}

	void onUdpSendComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error);
	void onUdpReceiveComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error);

private:
	IOCPService* m_service;
	UDPProxyHandler* m_pProxyHandler;
	
	char		m_proxyAddress[28];
	int			m_proxyAddressLen;

	tOvDataSet m_ovDataSet;
	AutoCriticalSection m_cs;

	tSocketMap m_socketMap;
};

