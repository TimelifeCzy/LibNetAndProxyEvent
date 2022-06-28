#include "TCPProxy.h"

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

}
void TCPProxy::execute() 
{

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

	} while (false);

	return true;
}

void TCPProxy::free()
{
}