#ifndef TRACEENGIN_MAPS_H
#define TRACEENGIN_MAPS_H

#include "traceEngin.h"

// ring buffer
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 256 * 1024);  // 256 KB
// } ringBuffer SEC(".maps");

// create a map to hold the network information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, struct NetworkEvent);
} networkMap SEC(".maps");

#endif