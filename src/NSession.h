#pragma one
#include "Utiliy.h"

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

private:
    NF_TCP_CONN_INFO    m_ci;
};