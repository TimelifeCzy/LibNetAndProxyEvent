#include "AsioService.h"
#include <memory>
#include <mutex>

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
    memset(m_recvBufLocal, 0, sizeof(m_recvBufLocal));
    return true;
}

const bool AsioService::AsioSvcFree()
{
    try
    {
        if(m_AcceptIpv4)
        {
            m_AcceptIpv4->cancel();
            m_AcceptIpv4->close();
            delete m_AcceptIpv4;
            m_AcceptIpv4 = nullptr;
        }
        if(m_AcceptIpv6)
        {
            m_AcceptIpv6->cancel();
            m_AcceptIpv6->close();
            delete m_AcceptIpv6;
            m_AcceptIpv6 = nullptr;
        }

        m_io_context.stop();
        for (std::size_t i = 0; i < m_threads.size(); ++i)
            m_threads[i]->join();
        m_threads.clear();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return false;
    }    
    return true;
}

void AsioService::Recv_local_complete(const boost::system::error_code& error, const size_t bytes_transferred, const sock_ptr sock)
{
    try
    {
        if(error)
        {
            std::cout << "IP:" << sock->remote_endpoint().address() << "断开连接" << std::endl;
            sock->close();
            return;
        }

        if (bytes_transferred > 0)
        {
            std::cout<< "IP:" << sock->remote_endpoint().address() << " 发来数据:" << m_recvBufLocal << std::endl;
            // DbgPrint("NFSession::recv_local_complete[%s] %d", m_recvBufLocal, bytes_transferred);
            // std::cout << "Session::Recv_local_complete " << m_recvBufLocal << " Lens: " << bytes_transferred << std::endl;
            sock->async_read_some( 
                boost::asio::buffer(m_recvBufLocal, sizeof(m_recvBufLocal)),
                boost::bind(&AsioService::Recv_local_complete, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred,
                    sock));

            // Send To Client
            // const std::string& msg = "Client Hello";
            // const auto write_size = (uint32_t)msg.size();
            // std::array<boost::asio::const_buffer, 2> write_buffers;
            // write_buffers[0] = boost::asio::buffer(&write_size, sizeof(uint32_t));
            // write_buffers[1] = boost::asio::buffer(msg.data(), write_size);
            // boost::asio::async_write(sock, write_buffers,
            //     [this](boost::system::error_code ec, std::size_t length) {
            //     if (ec) {
            //         std::cout << ec.message() << '\n';
            //         return;
            //     }
            // std::unique_lock<std::mutex> lock(m_wirteck);
            //});
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

void AsioService::Accept_HandlerIpv4(const boost::system::error_code& ec, const sock_ptr sock)
{
    std::cout << "IP:" << sock->remote_endpoint().address() << " Accept_HandlerIpv4" << std::endl;
    if(ec)
    {
        std::cout << "IP:" << sock->remote_endpoint().address() << "断开连接" << std::endl;
        sock->close();
        return;
    }

    sock->async_read_some(boost::asio::buffer(m_recvBufLocal, sizeof(m_recvBufLocal)),
        boost::bind(
            &AsioService::Recv_local_complete, 
            this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred,
            sock));
    
    // 发送完毕后继续监听，否则io_service将认为没有事件处理而结束运行 
    StartAcceptIpv4();
}

void AsioService::StartAcceptIpv4()
{
    try
    {
        if(!m_AcceptIpv4)
            return;
        std::cout << "StartAcceptIpv4" << std::endl;
        sock_ptr sock(new sock_t(m_io_context));
        // Accept Client Notify Ipv4
        m_AcceptIpv4->async_accept(*sock, boost::bind(&AsioService::Accept_HandlerIpv4, this, boost::asio::placeholders::error, sock));
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
        // m_AcceptIpv6->async_accept(,)
    }
    catch(...)
    {
    }
}

const bool AsioService::AsioRegisterSocket()
{
    // Init Asio Object Ipv4
    for (m_portIPv4 = 5555; m_portIPv4 < 5557; ++m_portIPv4)
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
        AsioService::StartAcceptIpv4();
        break;
    }


    // Init Asio Object Ipv6
    // for(m_portIPv6 = 8180; m_portIPv6 < 8120; ++m_portIPv6)
    // {
        
    //     try
    //     {
    //         m_AcceptIpv6 = new tcp::acceptor(m_io_context, tcp::endpoint(tcp::v6(), m_portIPv6));
    //     }
    //     catch(const std::exception& e)
    //     {
    //         std::cerr << e.what() << '\n';
    //         continue;
    //     }
    //     StartAcceptIpv6();
    //     break;
    // }
    
    for (std::size_t i = 0; i < 2; ++i)
    {
        std::shared_ptr<std::thread> thread(new std::thread(
            boost::bind(&boost::asio::io_context::run, &m_io_context)));
        m_threads.push_back(thread);
    }
    return true;
}