/*
    AsioService
*/
#pragma one
#include "Utiliy.h"

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

typedef tcp::socket sock_t;
typedef std::shared_ptr<sock_t> sock_ptr;

class AsioService
{
public:
    AsioService();
    ~AsioService();
public:
    const bool AsioSvcInit();
    const bool AsioSvcFree();
    const bool AsioRegisterSocket();

protected:
    void StartAcceptIpv4();
    void StartAcceptIpv6();
    void Accept_HandlerIpv4(const boost::system::error_code& ec, const sock_ptr sock);
    void Recv_local_complete(const boost::system::error_code& error, const size_t bytes_transferred, const sock_ptr sock);
    void Send_remote_complete(const boost::system::error_code& error, size_t bytes_transferred,  const sock_ptr sock);

private:
    tcp::acceptor * m_AcceptIpv4;
    tcp::acceptor * m_AcceptIpv6;
    int m_portIPv4;
    int m_portIPv6;
    char m_recvBufLocal[PACKET_LEN];
    boost::asio::io_context m_io_context;
    std::vector<std::shared_ptr<std::thread>> m_threads;
    
    std::mutex m_wirteck;
    typedef std::vector<char> tBuffer;
	typedef boost::shared_ptr<tBuffer> tBuffer_ptr;
    typedef std::queue<tBuffer_ptr> tBuffers;
    tBuffers m_sendBufRemote;
};