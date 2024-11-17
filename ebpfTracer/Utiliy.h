#ifndef _UTILIY_H
#define _UTILIY_H

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <iostream>
#include <sys/resource.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <logging/easylogging++.h>

#include "SingletonHandler.h"

#define EXEC_CMD_LEN 128
#define PACKET_LEN	8192
#define NF_MAX_ADDRESS_LENGTH		28
#define NF_MAX_IP_ADDRESS_LENGTH	16
#define MAX_TRIGGERS 10

typedef unsigned long long   ENDPOINT_ID;

typedef struct _NF_TCP_CONN_INFO
{
	unsigned long	filteringFlag;	// See NF_FILTERING_FLAG
	unsigned long	processId;		// Process identifier
	unsigned char	direction;		// See NF_DIRECTION
	unsigned short	ip_family;		// AF_INET for IPv4 and AF_INET6 for IPv6
	
	// Local address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	localAddress[NF_MAX_ADDRESS_LENGTH]; 
	
	// Remote address as sockaddr_in for IPv4 and sockaddr_in6 for IPv6
	unsigned char	remoteAddress[NF_MAX_ADDRESS_LENGTH];
} NF_TCP_CONN_INFO, * PNF_TCP_CONN_INFO;

enum TriggerType
{
	Processor,
	Commit,
	Timer,
	Signal,
	ThreadCount,
	FileDescriptorCount,
	Exception,
	GCThreshold,
	GCGeneration,
	Restrack
};

struct TriggerThread
{
	pthread_t thread;
	enum TriggerType trigger;
};

struct TraceEnginConfiguration
{
	// Enable
	bool bEnablebpf;

	// Process and System info
	pid_t ProcessId;
	pid_t ProcessGroup;         // -pgid
	bool bProcessGroup;         // -pgid

	// multithreading
	// set max number of concurrent dumps on init (default to 1)
	int nThreads;
	struct TriggerThread Threads[MAX_TRIGGERS];
	pthread_mutex_t ptrace_mutex;
	pthread_cond_t dotnetCond;
	pthread_mutex_t dotnetMutex;
	bool bSocketInitialized;
};

#endif