#ifndef TRACEENGIN_H
#define TRACEENGIN_H

#define MAX_PERCPU_BUFSIZE      (1 << 15)
#define TASK_COMM_LEN           16

#define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)
#define READ_KERN(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                      \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);                      \
        _val;                                                                  \
    })
#define READ_USER(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                      \
        bpf_core_read_user((void *)&_val, sizeof(_val), &ptr);                 \
        _val;                                                                  \
    })

/* map macro defination */
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)            \
    struct {                                                                   \
        __uint(type, _type);                                                   \
        __uint(max_entries, _max_entries);                                     \
        __type(key, _key_type);                                                \
        __type(value, _value_type);                                            \
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
BPF_PERF_OUTPUT(exec_events, 1024);
BPF_PERF_OUTPUT(file_events, 1024);
BPF_PERF_OUTPUT(net_events, 1024);

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define TC_ACT_UNSPEC       (-1)
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2

struct proc_ctx {
    __u64 mntns_id;
    __u32 netns_id;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u8 comm[TASK_COMM_LEN];
};

struct network_ctx {
    bool ingress;
    uint32_t pid;
    uint32_t protocol;
    uint32_t ifindex;
    uint32_t local_address;
    uint32_t remote_address;
    struct in6_addr local_address_v6;
    struct in6_addr remote_address_v6;
    uint32_t local_port;
    uint32_t remote_port;
    uint32_t packet_size;
    uint64_t timestamp;

    struct proc_ctx socket_proc;
};

#endif /* TRACEENGIN_H */