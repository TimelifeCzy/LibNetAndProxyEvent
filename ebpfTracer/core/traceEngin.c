// #include <linux/bpf.h>
// #include <stdbool.h>
// #include <stddef.h>
// #include <stdint.h>

// #include <linux/ip.h>
// #include <linux/ipv6.h>
// #include <linux/if_ether.h>
// #include <linux/tcp.h>
// #include <linux/udp.h>
// #include <net.h>
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "traceEngin.h"
#include "traceEngin_maps.h"

#include <string.h>

/*
inline int ip_str_to_value(int type, char* ip)
{
    struct in_addr s;
    inet_pton(type, ip, (void*)&s);
    return s.s_addr;
}

inline void ip_value_to_str(int type, int ip, char* result, int size)
{
    inet_ntop(type, (void*)&ip, result, size);
}
*/

__attribute__((always_inline))
static bool skb_revalidate_data(struct __sk_buff* skb, uint8_t** head, uint8_t** tail, const __u32 offset)
{
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }
        *head = (uint8_t*)(long)skb->data;
        *tail = (uint8_t*)(long)skb->data_end;
        if (*head + offset > *tail) {
            return false;
        }
    }
    return true;
}

__attribute__((always_inline))
static int parse_packet_tc(struct __sk_buff* skb, bool ingress)
{
    if(!skb || (NULL == skb))
        return 0;
    
    // packet pre check
    uint8_t* packet_start = (uint8_t*)(long)skb->data;
    uint8_t* packet_end = (uint8_t*)(long)skb->data_end;
    if (packet_start + sizeof(struct ethhdr) > packet_end)
        return TC_ACT_UNSPEC;
    
    struct ethhdr* eth = (struct ethhdr*)packet_start;
    if(!eth || (NULL == eth))
        return TC_ACT_UNSPEC;

    // get ip hdr packet
    uint32_t hdr_off_len = 0;
    struct network_ctx net_ctx = { 0, };
    const int type = bpf_ntohs(eth->h_proto);
    if(type == ETH_P_IP) {
        hdr_off_len = sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (!skb_revalidate_data(skb, &packet_start, &packet_end, hdr_off_len))
            return TC_ACT_UNSPEC;
        struct iphdr* ip = (void*)packet_start + sizeof(struct ethhdr);
        if (!ip || (NULL == ip))
            return TC_ACT_UNSPEC;
        net_ctx.local_address = ip->saddr;
        net_ctx.remote_address = ip->daddr;
        net_ctx.protocol = ip->protocol;
    }
    else if( type == ETH_P_IPV6) {
        hdr_off_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if (!skb_revalidate_data(skb, &packet_start, &packet_end, hdr_off_len))
            return TC_ACT_UNSPEC;
        struct ipv6hdr* ip6 = (void*)packet_start + sizeof(struct ethhdr);
        if (!ip6 || (NULL == ip6))
            return TC_ACT_UNSPEC;
        net_ctx.local_address_v6 = ip6->saddr;
        net_ctx.remote_address_v6 = ip6->daddr;
        net_ctx.protocol = ip6->nexthdr;
    }
    else
        return TC_ACT_UNSPEC;

    // get network hdr packet
    if (IPPROTO_TCP == net_ctx.protocol) {
        if (!skb_revalidate_data(skb, &packet_start, &packet_end, hdr_off_len + sizeof(struct tcphdr)))
            return TC_ACT_UNSPEC;
        struct tcphdr* tcp = (void*)packet_start + hdr_off_len;
        if (!tcp || (NULL == tcp))
            return TC_ACT_UNSPEC;
        net_ctx.local_port = tcp->source;
        net_ctx.remote_port = tcp->dest;
    }
    else if (IPPROTO_UDP == net_ctx.protocol) {
        if (!skb_revalidate_data(skb, &packet_start, &packet_end, hdr_off_len + sizeof(struct udphdr)))
            return TC_ACT_UNSPEC;
        struct udphdr* udp = (void*)packet_start + hdr_off_len;
        if (!udp || (NULL == udp))
            return TC_ACT_UNSPEC;
        net_ctx.local_port = udp->source;
        net_ctx.remote_port = udp->dest;
    }
    else
        return TC_ACT_UNSPEC;

    net_ctx.pid = 0;
    net_ctx.ingress = ingress;
    net_ctx.packet_size = skb->len;
    net_ctx.ifindex = skb->ifindex;
    net_ctx.timestamp = bpf_ktime_get_ns();
    
    const size_t pkt_size = sizeof(net_ctx);
    bpf_perf_event_output(skb, &eventMap, BPF_F_CURRENT_CPU, &net_ctx, pkt_size);

    if (type == ETH_P_IP) {
        const char fmt_str[] = "[eBPF tc] %s";
        const char fmt_str_local[] = " local: %u:%d\t";
        const char fmt_str_remote[] = "remote: %u:%d\n";
        if (IPPROTO_UDP == net_ctx.protocol) {
            const char chproto[] = "UDP";
            bpf_trace_printk(fmt_str, sizeof(fmt_str), chproto);
        }
        else if(IPPROTO_TCP == net_ctx.protocol){
            const char chproto[] = "TCP";
            bpf_trace_printk(fmt_str, sizeof(fmt_str), chproto);
        }
        else {
            const char chproto[] = "Unknown";
            bpf_trace_printk(fmt_str, sizeof(fmt_str), chproto);
        }
        bpf_trace_printk(fmt_str_local, sizeof(fmt_str_local), net_ctx.local_address, net_ctx.local_port);
        bpf_trace_printk(fmt_str_remote, sizeof(fmt_str_remote), net_ctx.remote_address, net_ctx.remote_port);
    }
    return TC_ACT_UNSPEC;
};

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int classifier_ingress(struct __sk_buff* skb)
{
    if (skb)
        return parse_packet_tc(skb, true);
    return 0;
}

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_EGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int classifier_egress(struct __sk_buff* skb)
{
    if(skb)
        return parse_packet_tc(skb, false);
    return 0;
}

/*
SEC("kprobe/tcp_v4_send_reset")
int kprobe_tcp_v4_send_reset(struct pt_regs* ctx)
{
    if (ctx == NULL || (!ctx))
        return 0;
    struct sock* sk = NULL;
    struct network_ctx net_ctx = { 0, };
    sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (sk) {
        // struct proc_ctx socket_proc = { 0, };
        // get_socket_proc(&socket_proc, sk);
        // net_ctx.socket_proc.pid = socket_proc.pid;
        // net_ctx.socket_proc.tid = socket_proc.tid;
        // net_ctx.socket_proc.uid = socket_proc.uid;
        // net_ctx.socket_proc.gid = socket_proc.gid;
        // net_ctx.socket_proc.mntns_id = socket_proc.mntns_id;
        // net_ctx.socket_proc.netns_id = socket_proc.netns_id;
        // __builtin_memcpy(net_ctx.socket_proc.comm, socket_proc.comm,
        //     sizeof(net_ctx.socket_proc.comm));

        // Get IP data
        net_ctx.local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        // Host expects data in host byte order
        net_ctx.remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        net_ctx.protocol = BPF_CORE_READ(sk, __sk_common.skc_family);
        if (net_ctx.protocol == 2) {
            net_ctx.local_address = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            net_ctx.remote_address = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        } else {
            BPF_CORE_READ_INTO(&net_ctx.local_address_v6, sk,
                            __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&net_ctx.remote_address_v6, sk,
                            __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        }

        const char fmt_str[] = "[eBPF kprobe] tcp_v4_send_reset localaddr: %d remoteaddr: %d \n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), net_ctx.local_address, net_ctx.remote_address);
    }
    else
    {
        const char fmt_str[] = "[eBPF kprobe] tcp v4 send reset PT_REGS_PARM1 error.\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str));
        struct sk_buff* skb = (struct sk_buff*)PT_REGS_PARM2(ctx);
    }
    return 0;
}
*/

/*
SEC("kprobe/ping_v4_sendmsg")
int BPF_KPROBE(trace_ping_v4_sendmsg)
{
    if(!ctx || (NULL==ctx))
        return 0;
    struct network_ctx net_ctx = { 0, };
    net_ctx.protocol = IPPROTO_ICMP;

    struct sock* sk = NULL;
    struct inet_sock* inet = NULL;
    struct msghdr* msg = NULL;
    struct sockaddr_in* addr = NULL;
    
    sk = (struct sock*)PT_REGS_PARM1(ctx);
    if(!sk || (NULL == sk))
        return 0;
    inet = (struct inet_sock *) sk;
    if(!inet || (NULL == inet))
        return 0;
    net_ctx.local_port = BPF_CORE_READ(inet, inet_sport);

    msg = (struct msghdr*)PT_REGS_PARM2(ctx);
    if (!msg || (NULL == msg))
        return 0; 
    addr = (struct sockaddr_in*)READ_KERN(msg->msg_name);
    if (!addr || (NULL == addr))
        return 0; 
    net_ctx.local_address = READ_KERN(addr->sin_addr).s_addr;

    const int pid = bpf_get_current_pid_tgid() >> 32;
    const char fmt_str[] = "[eBPF kp] ping v4 pid %d ping %u:%d.\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, net_ctx.local_address, net_ctx.local_port);

    return 0;
}
*/

/*
SEC("kretprobe/tcp_v4_rcv")
int tcp_v4_rcv_ret(struct pt_regs* ctx) {
    if (ctx == NULL || (!ctx))
        return 0;
    do
    {
        struct sk_buff* skb = (struct sk_buff*)PT_REGS_PARM1(ctx);
        if (!skb || (skb == NULL))
            break;

        // get skb info
        const u64 time = bpf_ktime_get_ns();
        const int pid = bpf_get_current_pid_tgid() >> 32;
        const char fmt_str[] = "[eBPF kp] tcp v4 rcv pid %d time %llu.\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, time);
    } while (false);

    return 0;
}

SEC("kretprobe/tcp_v6_rcv")
int tcp_v6_rcv_ret(struct pt_regs* ctx) {
    if (ctx == NULL || (!ctx))
        return 0;
    do
    {
        struct sk_buff* skb = (struct sk_buff*)PT_REGS_PARM1(ctx);
        if (!skb || (skb == NULL))
            break;

        // get skb info
        const u64 time = bpf_ktime_get_ns();
        const int pid = bpf_get_current_pid_tgid() >> 32;
        const char fmt_str[] = "[eBPF kp] tcp v6 rcv pid %d time %llu.\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, time);
    } while (false);

    return 0;
}
*/

/*
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_syscalls_sysentrywrite(struct syscall_enter_args* ctx)
{
    const int pid = bpf_get_current_pid_tgid() >> 32;
    const char fmt_str[] = "[eBPF sys_enter_execve] triggered from PID %d.\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tp_sys_exit_execve(void* ctx)
{
    const int pid = bpf_get_current_pid_tgid() >> 32;
    const char fmt_str[] = "[eBPF sys_exit_execve] triggered from PID %d.\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), pid);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int tp_sched_process_fork(struct trace_event_raw_sched_process_fork* ctx) {
    if (ctx == NULL || (!ctx)) 
        return 0;
    const int pid = ctx->parent_pid;
    const char fmt_str[] = "[eBPF tp sched] process fork pid %d.\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), pid);    
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    if (ctx == NULL || (!ctx))
        return 0;
    struct task_struct* task = NULL;
    task = (struct task_struct*)bpf_get_current_task();
    if (task == NULL || (!task))
        return 0;
    const int pid = bpf_get_current_pid_tgid() >> 32;
    const int ppid = BPF_CORE_READ(task, real_parent, pid);
    const int exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    const char fmt_str[] = "[eBPF tp sched] process exit pid %d exitcode %d.\n";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, exit_code);
    return 0;
}
*/

char LICENSE[] SEC("license") = "GPL";