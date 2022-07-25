/*
    asioService
*/
#pragma one

#include <sys/types.h>
#include <sys/socket.h>
#include "Utiliy.h"

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

class AsioService
{
public:
    AsioService();
    ~AsioService();
public:
    const bool AsioSvcInit();
    const bool AsioSvcFree();
    const bool AsioRegisterSocket();

private:
    tcp::acceptor * m_AcceptIpv4;
    tcp::acceptor * m_AcceptIpv6;
    boost::asio::io_context m_io_context;
    int m_port;
};