// LinuxNet.cpp: 定义应用程序的入口点。
//

#include "LinuxNet.h"
#include "AsioService.h"
#include <semaphore.h>
using namespace std;

static sem_t g_sem;
static unsigned WINAPI start_routine(void* )
{
	sem_wait(&sem);
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
	AsioService obj;
	return 0;
}
