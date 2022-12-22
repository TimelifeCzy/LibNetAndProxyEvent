#include "NSession.h"

NSession::NSession()
{
}

NSession::~NSession()
{
}

// Acc Success to Notify
const bool NSession::SessionStart()
{
    std::cout << "SessionStart" << std::endl;

    try
    {
        // SET Socket Staus
        boost::asio::socket_base::keep_alive option(true);
        m_socketLocal.set_option(option);

        boost::asio::ip::tcp::on_delay nd_option(true);
        m_socketLocal.set_option(nd_option);

        // Get Socket Info
        const boost::asio::ip::tcp::endpoint remoteEndpoint = m_socketLocal.remote_endpoint();
		const boost::asio::ip::tcp::endpoint localEndpoint = m_socketLocal.local_endpoint();

		m_ci.processId = 0;
		// m_ci.direction = NF_D_OUT;
		// m_ci.filteringFlag = NF_FILTER;
		m_ci.ip_family = remoteEndpoint.protocol().family();

        // If Proxy Save RealRemote
        boost::asio::ip::tcp::endpoint real_remoteEndpoint;
		if (remoteEndpoint.protocol().family() == AF_INET)
		{
			memcpy(&m_ci.localAddress, remoteEndpoint.data(), sizeof(sockaddr_in));
			{
				socklen_t socklen = sizeof(struct sockaddr_in);
				int error;

				error = getsockopt(m_socketLocal.native_handle(), SOL_IP, SO_ORIGINAL_DST, m_ci.remoteAddress, &socklen);
				if (error) 
				{
					DbgPrint("NFSession::start() getsockopt error %d", error);
					return false;
				}
			}

            if ((((sockaddr_in*)m_ci.remoteAddress)->sin_addr.s_addr == 
				((sockaddr_in*)localEndpoint.data())->sin_addr.s_addr) &&
				(((sockaddr_in*)m_ci.remoteAddress)->sin_addr.s_addr !=
				((sockaddr_in*)remoteEndpoint.data())->sin_addr.s_addr))
			{
				// Inbound connection to a local address
				// m_ci.direction = NF_D_IN;			
			}

            real_remoteEndpoint = boost::asio::ip::tcp::endpoint(
						boost::asio::ip::address_v4(htonl(((sockaddr_in*)m_ci.remoteAddress)->sin_addr.s_addr)), 
						htons(((sockaddr_in*)m_ci.remoteAddress)->sin_port));
            
				memcpy(m_ci.localAddress, m_ci.remoteAddress, sizeof(m_ci.localAddress));
				memcpy(m_ci.remoteAddress, remoteEndpoint.data(), sizeof(sockaddr_in));

            DbgPrint("NFSession::start() connect local=%s:%d remote=%s:%d", 
                            sLocalAddr.c_str(), ntohs(((sockaddr_in*)m_ci.localAddress)->sin_port),
                            sRemoteAddr.c_str(), ntohs(((sockaddr_in*)m_ci.remoteAddress)->sin_port));
        }
        
        // Bind Recv & Send
        m_socketRemote.async_read_some(boost::asio::buffer(m_recvBufRemote, sizeof(m_recvBufRemote)),
                boost::bind(&NFSession::recv_remote_complete, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
        
        boost::asio::async_write(m_socketLocal,
				  boost::asio::buffer(&(*m_sendBufLocal.front())[0], m_sendBufLocal.front()->size()),
				  boost::bind(&NFSession::send_local_complete, 
					shared_from_this(),
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));

    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}