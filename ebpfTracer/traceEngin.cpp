#include "Utiliy.h"

#define SEC(name) __attribute__((section(name), used))

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscall_enter_args *ctx)
{
    //__u64 id = bpf_get_current_pid_tgid();
    return 1;
}

int main(void) {
    std::cout << "ebpf Trace Use Case Start." << std::endl;
    std::cout << "ebpf Trace Use Case End." << std::endl;
    return 0;
}