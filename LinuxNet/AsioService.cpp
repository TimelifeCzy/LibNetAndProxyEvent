#include "NSession.h"
#include "AsioService.h"

typedef boost::shared_ptr<NSession> g_NSessionptr;

AsioService::AsioService()
{
    m_port = 0;
    m_AcceptIpv4 = nullptr;
    m_AcceptIpv6 = nullptr;
}

AsioService::~AsioService()
{

}

const bool AsioService::AsioSvcInit()
{
    return true;
}
const bool AsioService::AsioSvcFree()
{
    return true;
}

const bool AsioService::AsioRegisterSocket()
{
    try
    {
        m_AcceptIpv4 = new tcp::acceptor(m_io_context, tcp::endpoint(tcp::v4(), m_port));
        m_AcceptIpv6 = new tcp::acceptor(m_io_context, tcp::endpoint(tcp::v6(), m_port));   
    }
    catch(const std::exception& e)
    {
        return false;
    }


    g_NSessionptr new_session();

    return true;
}