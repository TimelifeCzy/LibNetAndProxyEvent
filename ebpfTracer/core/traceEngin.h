#ifndef TRACEENGIN_H
#define TRACEENGIN_H

#define TASK_COMM_LEN           16
#define INET_ADDRSTRLEN_EX      16
#define INET6_ADDRSTRLEN_EX     46

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