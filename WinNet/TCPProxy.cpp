#include "TCPProxy.h"
#include "linkedlist.h"
#include <mstcpip.h>

static const int NF_MAX_ADDRESS_LENGTH = 28;

TCPProxy::TCPProxy()
{
	m_listenSocket = INVALID_SOCKET;
	m_acceptSocket = INVALID_SOCKET;
	m_listenSocket_IPv6 = INVALID_SOCKET;
	m_acceptSocket_IPv6 = INVALID_SOCKET;
	m_port = 0;
}
TCPProxy::~TCPProxy()
{
}

void TCPProxy::onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED* pOverlapped, int error)
{
	OV_DATA * pov = (OV_DATA*)pOverlapped;
	pov->socket = socket;
	pov->dwTransferred = dwTransferred;
	pov->error = error;

	{
		AutoLock lock(m_csEventList);
		// Insert EventList
		InsertTailList(&m_eventList, &pov->entryEventList);
	}
	// Start Pool
	m_pool.jobAvailable();
}
void TCPProxy::execute() 
{
	OV_DATA* pov;

	{
		AutoLock lock(m_csEventList);
		pov = CONTAINING_RECORD(m_eventList.Flink, OV_DATA, entryEventList);
		RemoveEntryList(&pov->entryEventList);
		InitializeListHead(&pov->entryEventList);
	}

	if (pov)
	{
		switch (pov->type)
		{
		case OVT_ACCEPT:
			onAcceptComplete(pov->socket, pov->dwTransferred, pov, pov->error);
			break;
		case OVT_CONNECT:
			onConnectComplete(pov->socket, pov->dwTransferred, pov, pov->error);
			break;
		case OVT_SEND:
			onSendComplete(pov->socket, pov->dwTransferred, pov, pov->error);
			break;
		case OVT_RECEIVE:
			onReceiveComplete(pov->socket, pov->dwTransferred, pov, pov->error);
			break;
		case OVT_CLOSE:
			onClose(pov->socket, pov->dwTransferred, pov, pov->error);
			break;
		default:
			break;
		}

		deleteOV_DATA(pov);
	}

	{
		AutoLock lock(m_csEventList);
		if (!IsListEmpty(&m_eventList))
		{
			m_pool.jobAvailable();
		}
	}

}
void TCPProxy::threadStarted()
{
}
void TCPProxy::threadStopped()
{
}

void* GetExtensionFunction(SOCKET s, const GUID* which_fn)
{
	void* ptr = NULL;
	DWORD bytes = 0;
	WSAIoctl(s,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		(GUID*)which_fn, sizeof(*which_fn),
		&ptr, sizeof(ptr),
		&bytes,
		NULL,
		NULL);
	return ptr;
}
bool TCPProxy::initExtensions()
{
	const GUID acceptex = WSAID_ACCEPTEX;
	const GUID connectex = WSAID_CONNECTEX;
	const GUID getacceptexsockaddrs = WSAID_GETACCEPTEXSOCKADDRS;

	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
		return false;

	m_pAcceptEx = (LPFN_ACCEPTEX)GetExtensionFunction(s, &acceptex);
	m_pConnectEx = (LPFN_CONNECTEX)GetExtensionFunction(s, &connectex);
	m_pGetAcceptExSockaddrs = (LPFN_GETACCEPTEXSOCKADDRS)GetExtensionFunction(s, &getacceptexsockaddrs);

	closesocket(s);

	return m_pAcceptEx != NULL && m_pConnectEx != NULL && m_pGetAcceptExSockaddrs != NULL;
}

void TCPProxy::SetKeepAliveVals(SOCKET s)
{
	tcp_keepalive tk;
	DWORD dwRet;

	{
		AutoLock lock(m_cs);

		tk.onoff = 1;
		tk.keepalivetime = m_timeout;
		tk.keepaliveinterval = 1000;
	}

	int err = WSAIoctl(s, SIO_KEEPALIVE_VALS,
		(LPVOID)&tk,
		(DWORD)sizeof(tk),
		NULL,
		0,
		(LPDWORD)&dwRet,
		NULL,
		NULL);
	if (err != 0)
	{
		OutputDebugString(L"TCPProxy::setKeepAliveVals WSAIoctl");
	}
}
bool TCPProxy::StartAccept(int ipFamily)
{
	SOCKET s  =WSASocket(ipFamily, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (s == INVALID_SOCKET)
		return false;

	OV_DATA* pov = newOV_DATA();
	DWORD dwBytes;

	pov->type = OVT_ACCEPT;
	pov->packetList.push_back(TCP_PACKET(NULL, 2 * (sizeof(sockaddr_in6) + 16)));

	if (ipFamily == AF_INET)
	{
		m_acceptSocket = s;
	}
	else
	{
		m_acceptSocket_IPv6 = s;
	}

	if (!m_pAcceptEx( (ipFamily == AF_INET) ? m_listenSocket : m_listenSocket_IPv6, 
		s, 
		pov->packetList[0].buffer.buf,
		0,
		sizeof(sockaddr_in6) + 16,
		sizeof(sockaddr_in6) + 16,
		&dwBytes,
		&pov->ol) )
	{
		if (WSAGetLastError() != ERROR_IO_PENDING)
		{
			closesocket(s);
			deleteOV_DATA(pov);
			return false;
		}
	}
	return true;
}
bool TCPProxy::StartConnect(SOCKET socket, sockaddr* pAddr, int addrLen, __int64 id)
{
	return true;
}
//bool TCPProxy::StartTcpSend(PROXY_DATA* pd, bool isInSocket, const char* buf, int len, NFAPI_NS ENDPOINT_ID id)
//{
//}
bool TCPProxy::startClose(SOCKET socket, __int64 id)
{
	return true;
}

void TCPProxy::onAcceptComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
{// client 连接本地代理成功
	SOCKET acceptSocket;
	int ipFamily;
	bool result = false;
	if (socket == m_listenSocket)
	{
		acceptSocket = m_acceptSocket;
		ipFamily = AF_INET;
	}
	else
	{
		acceptSocket = m_acceptSocket_IPv6;
		ipFamily = AF_INET6;
	}
	if (error != 0)
	{
		OutputDebugString(L"TCPProxy::onAcceptComplete() failed, err=%d");
		closesocket(acceptSocket);
		if (!StartAccept(ipFamily))
		{
			OutputDebugString(L"TCPProxy::startAccept() failed");
		}
		return;
	}

	sockaddr* pLocalAddr = NULL;
	sockaddr* pRemoteAddr = NULL;
	int localAddrLen, remoteAddrLen;
	char	realRemoteAddress[NF_MAX_ADDRESS_LENGTH];

	m_pGetAcceptExSockaddrs(pov->packetList[0].buffer.buf,
		0,
		sizeof(sockaddr_in6) + 16,
		sizeof(sockaddr_in6) + 16,
		&pLocalAddr,
		&localAddrLen,
		&pRemoteAddr,
		&remoteAddrLen);

	{
	}

	BOOL val = 1;
	m_service.iocpSvcRegisterSocket(acceptSocket);
	setsockopt(acceptSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&m_listenSocket, sizeof(m_listenSocket));
	setsockopt(acceptSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&val, sizeof(val));
	setsockopt(acceptSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&val, sizeof(val));
	SetKeepAliveVals(acceptSocket);
	
	{
	
	}

	if (!StartAccept(ipFamily))
	{
		OutputDebugString(L"TCPProxy::startAccept() failed");
	}
}
void TCPProxy::onConnectComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
{
	if (error != 0)
	{
		OutputDebugString(L"TCPProxy::onConnectComplete failed");
		startClose(socket, pov->id);
		return;
	}

}
void TCPProxy::onSendComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
{
	
}
void TCPProxy::onReceiveComplete(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
{
}
void TCPProxy::onClose(SOCKET socket, DWORD dwTransferred, OV_DATA* pov, int error)
{
}

// Local Proxy Init
bool TCPProxy::init(unsigned short port, bool bindToLocalhost, int threadCount)
{
	bool result = false;
	m_port = port;

	if (!initExtensions())\
	{
		OutputDebugString(L"TCPProxy::init initExtensions() failed");
		return false;
	}
	
	do
	{
		// Init Iocp
		if (!m_service.iocpSvcInit(this))
		{
			OutputDebugString(L"TCPProxy::init m_service.init() failed");
			break;
		}

		// Init ThreadPool
		if (!m_pool.init(threadCount, this))
		{
			OutputDebugString(L"TCPProxy::init m_pool.init() failed");
			break;
		}

		// ipv4
		sockaddr_in addr;
		RtlSecureZeroMemory(&addr, sizeof(sockaddr_in));
		addr.sin_family = AF_INET;
		if (bindToLocalhost)
			inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr.S_un.S_addr);
		addr.sin_port = m_port;
		m_listenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (m_listenSocket == INVALID_SOCKET)
			break;
		if (0 != bind(m_listenSocket, (SOCKADDR*)&addr, sizeof(addr)))
			break;
		if (0 != listen(m_listenSocket, SOMAXCONN))
			break;
		m_service.iocpSvcRegisterSocket(m_listenSocket);
		// Accept
		if (!StartAccept(AF_INET))
			break;
		result = true;
	} while (false);

	return result;
}
void TCPProxy::free()
{
}