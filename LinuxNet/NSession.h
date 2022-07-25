#pragma one
#include <memory>

class NSession : public std::enable_shared_from_this<NSession>
{
public:
    NSession();
    ~NSession();
};