// LinuxNet.cpp: 定义应用程序的入口点。
//

#include "LinuxNet.h"
#include "AsioService.h"
#include <semaphore.h>
#include <memory>
using namespace std;

// static sem_t g_sem;
static void* start_routine(void* vParm)
{
	// Asio Server WorkItem
	//boost::asio::io_context asio_ctx;
	std::shared_ptr<AsioService> SvcSock = std::make_shared<AsioService>();
	SvcSock->AsioRegisterSocket();
	// Waiting Exit Event
	// sem_wait(&g_sem);
	sleep(1000 * 60 * 60);
	return nullptr;
}

int main()
{
	//sem_init(&g_sem,0,0);
	pthread_t pthr = 0;
	const int res = pthread_create(&pthr, NULL, start_routine, NULL);
	if(res != 0)
		return 0;
	//sme_post(&g_sem);
	pthread_join(pthr,NULL);
	//sem_destroy(&g_sem);
	return 0;
}
