/*
    AsioService
*/
#pragma one
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

protected:
    void StartAcceptIpv4();
    void StartAcceptIpv6();

private:
    tcp::acceptor * m_AcceptIpv4;
    tcp::acceptor * m_AcceptIpv6;
    boost::asio::io_context m_io_context;
    int m_portIPv4;
    int m_portIPv6;
};