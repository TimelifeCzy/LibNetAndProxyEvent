#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "traceEngin.h"
#include "traceEngin_maps.h"

__attribute__((always_inline))
static bool skb_revalidate_data(struct __sk_buff *skb, uint8_t **head, uint8_t **tail, const u32 offset)
{
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }
        *head = (uint8_t *) (long) skb->data;
        *tail = (uint8_t *) (long) skb->data_end;
        if (*head + offset > *tail) {
            return false;
        }
    }
    return true;
}

__attribute__((always_inline))
static int parse_packet(struct __sk_buff* skb, bool ingress)
{
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
    struct NetworkEvent pkt_ctx = { 0, };
    const int type = bpf_ntohs(eth->h_proto);
    if(type == ETH_P_IP) {
        hdr_off_len = sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (!skb_revalidate_data(skb, &packet_start, &packet_end, hdr_off_len))
            return TC_ACT_UNSPEC;
        struct iphdr* ip = (void*)packet_start + sizeof(struct ethhdr);
        if (!ip || (NULL == ip))
            return TC_ACT_UNSPEC;
        pkt_ctx.src_addr.in6_u.u6_addr32[3] = ip->saddr;
        pkt_ctx.dst_addr.in6_u.u6_addr32[3] = ip->daddr;
        pkt_ctx.src_addr.in6_u.u6_addr16[5] = 0xffff;
        pkt_ctx.dst_addr.in6_u.u6_addr16[5] = 0xffff;
        pkt_ctx.protocol = ip->protocol;      
    }
    else if( type == ETH_P_IPV6) {
        hdr_off_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if (!skb_revalidate_data(skb, &packet_start, &packet_end, hdr_off_len))
            return TC_ACT_UNSPEC;
        struct ipv6hdr* ip6 = (void*)packet_start + sizeof(struct ethhdr);
        if (!ip6 || (NULL == ip6))
            return TC_ACT_UNSPEC;
        pkt_ctx.src_addr = ip6->saddr;
        pkt_ctx.dst_addr = ip6->daddr;
        pkt_ctx.protocol = ip6->nexthdr;
    }
    else
        return TC_ACT_UNSPEC;

    // get network hdr packet
    if (IPPROTO_TCP == pkt_ctx.protocol) {
        if (!skb_revalidate_data(skb, &packet_start, &packet_end, hdr_off_len + sizeof(struct tcphdr)))
            return TC_ACT_UNSPEC;
        struct tcphdr* tcp = (void*)packet_start + hdr_off_len;
        if (!tcp || (NULL == tcp))
            return TC_ACT_UNSPEC;
        pkt_ctx.src_port = tcp->source;
        pkt_ctx.dst_port = tcp->dest;
    }
    else if (IPPROTO_UDP == pkt_ctx.protocol) {
        if (!skb_revalidate_data(skb, &packet_start, &packet_end, hdr_off_len + sizeof(struct udphdr)))
            return TC_ACT_UNSPEC;
        struct udphdr* udp = (void*)packet_start + hdr_off_len;
        if (!udp || (NULL == udp))
            return TC_ACT_UNSPEC;
        pkt_ctx.src_port = udp->source;
        pkt_ctx.dst_port = udp->dest;
    }
    else
        return TC_ACT_UNSPEC;

    pkt_ctx.pid = 0;
    pkt_ctx.ingress = ingress;
    pkt_ctx.packet_size = skb->len;
    pkt_ctx.ifindex = skb->ifindex;
    pkt_ctx.timestamp = bpf_ktime_get_ns();
    
    const size_t pkt_size = sizeof(pkt_ctx);
    bpf_perf_event_output(skb, &net_events, BPF_F_CURRENT_CPU, &pkt_ctx, pkt_size);
    return TC_ACT_UNSPEC;
};

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int classifier_ingress(struct __sk_buff* skb)
{
    if (skb)
        return parse_packet(skb, true);
    return 0;
}

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_EGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int classifier_egress(struct __sk_buff* skb)
{
    if(skb)
        return parse_packet(skb, false);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";