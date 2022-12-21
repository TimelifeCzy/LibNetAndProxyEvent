#include "AsioService.h"

AsioService::AsioService()
{
    AsioSvcInit();
}

AsioService::~AsioService()
{

}

const bool AsioService::AsioSvcInit()
{
    m_AcceptIpv4 = nullptr;
    m_AcceptIpv6 = nullptr;
    m_portIPv4 = 0;
    m_portIPv6 = 0;
    return true;
}
const bool AsioService::AsioSvcFree()
{
    return true;
}

void AsioService::StartAcceptIpv4()
{
    try
    {
        if(!m_AcceptIpv4)
            return;
        // Accept Client Notify Ipv4
        m_AcceptIpv4->async_accept(,)
    }
    catch(...)
    {
    }
}

void AsioService::StartAcceptIpv6()
{
    try
    {
        if(!m_AcceptIpv6)
            return;
        // Accept Client Notify Ipv6
        m_AcceptIpv6->async_accept(,)
    }
    catch(...)
    {
    }
}

const bool AsioService::AsioRegisterSocket()
{
    // Init Asio Object Ipv4
    for (m_portIPv4 = 8080; m_portIPv4 < 8180; ++m_portIPv4)
    {
        try
        {
            m_AcceptIpv4 = new tcp::acceptor(m_io_context, tcp::endpoint(tcp::v4(), m_portIPv4));
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            continue;
        }
        AcceptIpv4();
        break;
    }

    // Init Asio Object Ipv6
    for(m_portIPv6 = 8180; m_portIPv6 < 8120; ++m_portIPv6)
    {

        try
        {
            m_AcceptIpv6 = new tcp::acceptor(m_io_context, tcp::endpoint(tcp::v6(), m_portIPv6));
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            continue;
        }
        AcceptIpv6();
        break;
    }
    return true;
}