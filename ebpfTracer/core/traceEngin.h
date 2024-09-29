#ifndef __STDUNIX_H
#define __STDUNIX_H
#define EXEC_CMD_LEN 128

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct event {
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    char cmd[EXEC_CMD_LEN];
    unsigned long long ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} ringBuffer SEC(".maps");

#endif /* __STDUNIX_H */