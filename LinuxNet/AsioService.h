/*
    AsioService
*/
#pragma one
#include "Utiliy.h"
#include <mutex>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

typedef tcp::socket sock_t;
typedef std::shared_ptr<boost::asio::ip::tcp::socket> sock_ptr;

class AsioService
{
public:
    AsioService(boost::asio::io_context& icontext) : m_io_context(icontext)
    {
        AsioSvcInit();
    }
    ~AsioService();
public:
    const bool AsioSvcInit();
    const bool AsioSvcFree();
    const bool AsioRegisterSocket();

protected:
    void StartAcceptIpv4();
    void StartAcceptIpv6();
    void Accept_HandlerIpv4(const boost::system::error_code& ec, sock_ptr sock);
    void Recv_local_complete(const boost::system::error_code& error, const size_t bytes_transferred, const sock_ptr sock);

private:
    tcp::acceptor * m_AcceptIpv4;
    tcp::acceptor * m_AcceptIpv6;
    boost::asio::io_context& m_io_context;
    int m_portIPv4;
    int m_portIPv6;
    char m_recvBufLocal[PACKET_LEN];
    std::mutex m_wirteck;
};