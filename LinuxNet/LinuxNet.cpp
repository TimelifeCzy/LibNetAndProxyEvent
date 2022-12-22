// LinuxNet.cpp: 定义应用程序的入口点。
//

#include "LinuxNet.h"
#include "AsioService.h"
#include <semaphore.h>
using namespace std;

static sem_t g_sem;
static void* start_routine(void* vParm)
{
	// Asio Server WorkItem
	boost::asio::io_context asio_ctx;
	std::shared_ptr<AsioService> SvcSock = std::make_shared<AsioService>(asio_ctx);
	SvcSock->AsioRegisterSocket();
	
	// Waiting Exit Event
	sem_wait(&g_sem);
}

int main()
{
	sem_init(&g_sem,0,0);
	pthread_t pthr = 0;
	const int res = pthread_create(&pthr, NULL, start_routine, NULL);
	if(res && pthr)
	{
		sem_post(&g_sem);
		pthread_join(pthr,NULL);
		sem_destroy(&g_sem);
	}
	return 0;
}
