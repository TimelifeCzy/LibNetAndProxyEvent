#include "UDPProxy.h"

UDPProxy::UDPProxy()
{
}

UDPProxy::~UDPProxy()
{
}

bool UDPProxy::createProxyConnection(unsigned __int64 id)
{
	bool result = false;

	for (;;)
	{
		SOCKET udpSocket = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (udpSocket == INVALID_SOCKET)
		{
			return false;
		}

		{
			AutoLock lock(m_cs);
			PROXY_DATA* pd = new PROXY_DATA();
			pd->udpSocket = udpSocket;
			pd->remoteAddressLen = m_proxyAddressLen;
			memcpy(pd->remoteAddress, m_proxyAddress, m_proxyAddressLen);
			m_socketMap[id] = pd;
		}

		if (!m_service->iocpSvcRegisterSocket(udpSocket))
			break;

		result = true;

		break;
	}

	if (!result)
	{
		{
			AutoLock lock(m_cs);
			tSocketMap::iterator it = m_socketMap.find(id);
			if (it != m_socketMap.end())
			{
				delete it->second;
				m_socketMap.erase(it);
			}
		}
	}

	return result;
}

void UDPProxy::deleteProxyConnection(unsigned __int64 id)
{
	AutoLock lock(m_cs);
	tSocketMap::iterator it = m_socketMap.find(id);
	if (it != m_socketMap.end())
	{
		delete it->second;
		m_socketMap.erase(it);
	}
}

bool UDPProxy::udpSend(unsigned __int64 id, char* buf, int len, char* remoteAddress, int remoteAddressLen)
{
	bool nret = false;
	SOCKET s;
	{
		AutoLock lock(m_cs);
		tSocketMap::iterator it = m_socketMap.find(id);
		if (it == m_socketMap.end())
		{
			return false;
		}
		s = it->second->udpSocket;

		OV_DATA* pov = newOV_DATA();
		DWORD dwBytes;

		pov->type = OVT_UDP_SEND;
		pov->id = id;

		if (len > 0)
		{
			if (((sockaddr*)remoteAddress)->sa_family == AF_INET)
			{
				sockaddr_in* pAddr = (sockaddr_in*)remoteAddress;
				char head[20] = { 0 };
				head[0] = 0x01;
				*(DWORD*)(head + 1) = pAddr->sin_addr.S_un.S_addr;
				*(WORD*)(head + 5) = pAddr->sin_port;
				pov->buffer.resize(len + 7);
				memcpy(&pov->buffer[0], head, 7);
				memcpy(&pov->buffer[7], buf, len);
			}
			else
			{
				return false;
			}
		}

		WSABUF bufs;
		bufs.buf = &pov->buffer[0];
		bufs.len = (u_long)pov->buffer.size();
		if (WSASendTo(s, &bufs, 1, &dwBytes, 0, (sockaddr*)it->second->remoteAddress, it->second->remoteAddressLen, &pov->ol, NULL) != 0)
		{
			int err = WSAGetLastError();
			if (err != ERROR_IO_PENDING)
			{
				pov->type = OVT_UDP_RECEIVE;
				pov->buffer.clear();
				if (!m_service->iocpSvcPostCompletion(s, 0, &pov->ol))
				{
					deleteOV_DATA(pov);
			}
				return false;
		}
	}

		if (!it->second->udpRecvStarted)
		{
			it->second->udpRecvStarted = true;
			startUdpReceive(s, id, NULL);
		}
	}

	return nret;
}

bool UDPProxy::startUdpReceive(SOCKET socket, unsigned __int64 id, OV_DATA* pov)
{
	bool nret = false;

	if (pov == NULL)
	{
		pov = newOV_DATA();
		pov->type = OVT_UDP_RECEIVE;
		pov->id = id;
		pov->buffer.resize(PACKET_SIZE);
	}

	WSABUF bufs;
	bufs.buf = &pov->buffer[0];
	bufs.len = (u_long)pov->buffer.size();

	DWORD dwFlags = 0, dwBytes;

	pov->remoteAddressLen = sizeof(pov->remoteAddress);

	if (0 != WSARecvFrom(socket, &bufs, 1, &dwBytes, &dwFlags, (sockaddr*)pov->remoteAddress, &pov->remoteAddressLen, &pov->ol, NULL))
	{
		int err = WSAGetLastError();
		if (err != ERROR_IO_PENDING)
		{
			if (!m_service->iocpSvcPostCompletion(socket, 0, &pov->ol))
			{
				deleteOV_DATA(pov);
			}
			return true;
		}
	}
	return nret;
}

void UDPProxy::onUdpSendComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
{
	deleteOV_DATA(pov);
}

void UDPProxy::onUdpReceiveComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
{
	do
	{
		if (dwTransferred == 0)
		{
			deleteOV_DATA(pov);
			break;
		}

		if (dwTransferred > 7)
		{
			// ´úÀí
		}

		memset(&pov->ol, 0, sizeof(pov->ol));
		startUdpReceive(socket, pov->id, pov);
	
	} while (false);

}

void UDPProxy::onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED* pOverlapped, int error)
{
	OV_DATA* pov = (OV_DATA*)pOverlapped;
	switch (pov->type)
	{
	case OVT_UDP_SEND:
		onUdpSendComplete(socket, dwTransferred, pov, error);
		break;

	case OVT_UDP_RECEIVE:
		onUdpReceiveComplete(socket, dwTransferred, pov, error);
		break;
	}
}

bool UDPProxy::init(UDPProxyHandler* const pProxyHandler, char* proxyAddress, const int proxyAddressLen, bool bindToLocalhost)
{
	if (!m_service->iocpSvcInit(this))
		return false;
	m_pProxyHandler = pProxyHandler;
	memcpy(m_proxyAddress, proxyAddress, proxyAddressLen);
	m_proxyAddressLen = proxyAddressLen;
	return true;
}

void UDPProxy::free()
{
	m_service->iocpSvcFree();

	while (!m_ovDataSet.empty())
	{
		tOvDataSet::iterator it = m_ovDataSet.begin();
		delete (*it);
		m_ovDataSet.erase(it);
	}
	while (!m_socketMap.empty())
	{
		tSocketMap::iterator it = m_socketMap.begin();
		delete it->second;
		m_socketMap.erase(it);
	}
}