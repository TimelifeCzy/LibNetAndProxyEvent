#pragma one
#ifndef _COMMAND_H
#define _COMMAND_H

#include <sys/types.h>
#include <sys/socket.h>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <memory>
#include <thread>
#include <queue>

#include <bpf/bpf.h>

#define PACKET_LEN	8192
#define NF_MAX_ADDRESS_LENGTH		28
#define NF_MAX_IP_ADDRESS_LENGTH	16

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
} NF_TCP_CONN_INFO, *PNF_TCP_CONN_INFO;


#endif