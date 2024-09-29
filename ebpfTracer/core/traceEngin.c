#include "traceEngin.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
const int sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = 0;
    pid_t pid = 0;
    struct event* e = NULL;
    struct task_struct* task = NULL;

    uid_t uid = (u32)bpf_get_current_uid_gid();

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    task = (struct task_struct*)bpf_get_current_task();

    // read name 
    char* cmd = (char*)BPF_CORE_READ(ctx, args[0]);
    e = bpf_ringbuf_reserve(&ringBuffer, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = pid;
    e->uid = uid;
    e->ppid = BPF_CORE_READ(task, real_parent, pid);
    bpf_probe_read_str(&e->cmd, EXEC_CMD_LEN, cmd);
    e->ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);
    // bpf_printk("TRACEPOINT EXEC pid = %d, uid = %d, cmd = %s\n", pid, uid, e->cmd);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int snoop_process_exit(struct trace_event_raw_sched_process_template* ctx)
{
    pid_t pid = 0, tid = 0;
    u64 id, ts, * start_ts = NULL, start_time = 0;
    struct event* e = NULL;
    struct task_struct* task = NULL;

    uid_t uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    task = (struct task_struct*)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);

    /* ignore thread exits */
    if (pid != tid)
        return 0;
    
    e = bpf_ringbuf_reserve(&ringBuffer, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->uid = uid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->is_exit = true;
    e->retval = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->cmd, sizeof(e->cmd));

    bpf_ringbuf_submit(e, 0);
    // bpf_printk("TRACEPOINT EXIT pid = %d, uid = %d, cmd = %s\n", pid, uid, e->cmd);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
const int handle_tp(void *ctx)
{
    const int pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("BPF triggered from PID %d.\n", pid);
    return 0;
}