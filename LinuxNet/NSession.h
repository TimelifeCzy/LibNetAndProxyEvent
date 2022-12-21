#pragma one
#include <memory>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class NSession : 
    public std::enable_shared_from_this<NSession>
{
public:
    NSession();
    ~NSession();

    const bool SessionStart();


    tcp::socket  m_socketLocal;
	tcp::socket  m_socketRemote;
};