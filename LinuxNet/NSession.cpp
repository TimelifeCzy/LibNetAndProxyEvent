#include "Utiliy.h"
#include "NSession.h"

NSession::NSession()
{
}

NSession::~NSession()
{
}

const bool NSession::SessionStart()
{
    std::cout << "SessionStart" << std::endl;

    try
    {
        boost::asio::socket_base::keep_alive option(true);
        m_socketLocal.set_option(option);

        boost::asio::ip::tcp::on_delay nd_option(true);
        m_socketLocal.set_option(nd_option);

        boost::asio::ip::tcp::endpoint remoteEndpoint = m_socketLocal.remote_endpoint();
		boost::asio::ip::tcp::endpoint localEndpoint = m_socketLocal.local_endpoint();

        boost::asio::ip::tcp::endpoint real_remoteEndpoint;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}