#ifndef TRACEENGIN_MAPS_H
#define TRACEENGIN_MAPS_H

#include "traceEngin.h"

#define MAX_PERCPU_BUFSIZE      (1 << 15)

/* map macro defination */
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)            \
    struct {                                                                   \
        __uint(type, _type);                                                   \
        __type(key, _key_type);                                                \
        __type(value, _value_type);                                            \
        __uint(max_entries, _max_entries);                                     \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                  \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)
#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries)              \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)
#define BPF_LPM_TRIE(_name, _key_type, _value_type, _max_entries)              \
    BPF_MAP(_name, BPF_MAP_TYPE_LPM_TRIE, _key_type, _value_type, _max_entries)
#define BPF_ARRAY(_name, _value_type, _max_entries)                            \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, __u32, _value_type, _max_entries)
#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries)                     \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, _value_type, _max_entries)
#define BPF_PROG_ARRAY(_name, _max_entries)                                    \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, _max_entries)
#define BPF_PERF_OUTPUT(_name, _max_entries)                                   \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)
#define BPF_PERCPU_HASH(_name, _max_entries)                                   \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_HASH, int, int, _max_entries)
#define BPF_SOCKHASH(_name, _key_type, _value_type, _max_entries)              \
    BPF_MAP(_name, BPF_MAP_TYPE_SOCKHASH, _key_type, _value_type, _max_entries)
typedef struct simple_buf {
    __u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

/* perf_output for events */
// BPF_PERF_OUTPUT(exec_events, 1024);
// BPF_PERF_OUTPUT(file_events, 1024);
// BPF_PERF_OUTPUT(net_events, 1024);

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} eventMap SEC(".maps");

// create a map to hold the network information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct network_ctx);
    __uint(max_entries, 1024);
} networkMap SEC(".maps");

#endif