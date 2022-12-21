class NFSessionContainer
{
public:
	virtual bool deleteSession(unsigned long long id) = 0;
	virtual bool deleteSession_unsafe(unsigned long long id) = 0;
};