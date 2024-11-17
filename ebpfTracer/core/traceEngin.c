#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "traceEngin.h"
#include "traceEngin_maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static bool __attribute__((always_inline))
skb_revalidate_data(struct __sk_buff *skb, uint8_t **head, uint8_t **tail, const u32 offset)
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

static int __attribute__((always_inline))
parse_packet(struct __sk_buff* skb, bool ingress)
{
    uint8_t* start = (uint8_t*)(long)skb->data;
    uint8_t* end = (uint8_t*)(long)skb->data_end;
    
    // packet pre check
    if (start + sizeof(struct ethhdr) > end)
        return TC_ACT_UNSPEC;

    struct ethhdr* eth = (struct ethhdr*)start;
    if(!eth || (NULL == eth))
        return TC_ACT_UNSPEC;

    uint32_t hdr_off_len = 0;
    struct NetworkEvent pkt_ctx = { 0, };
    const int type = bpf_ntohs(eth->h_proto);
    if(type == ETH_P_IP) {
        hdr_off_len = sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (!skb_revalidate_data(skb, &start, &end, hdr_off_len))
            return TC_ACT_UNSPEC;
        // create a IPv4-Mapped IPv6 Address
        struct iphdr* ip = (void*)start + sizeof(struct ethhdr);
        if(ip) {
            pkt_ctx.src_addr.in6_u.u6_addr32[3] = ip->saddr;
            pkt_ctx.dst_addr.in6_u.u6_addr32[3] = ip->daddr;
            pkt_ctx.src_addr.in6_u.u6_addr16[5] = 0xffff;
            pkt_ctx.dst_addr.in6_u.u6_addr16[5] = 0xffff;
            pkt_ctx.protocol = ip->protocol;
        }
    }
    else if( type == ETH_P_IPV6) {
        hdr_off_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if (!skb_revalidate_data(skb, &start, &end, hdr_off_len))
            return TC_ACT_UNSPEC;

        struct ipv6hdr* ip6 = (void*)start + sizeof(struct ethhdr);
        if(ip6) {
            pkt_ctx.src_addr = ip6->saddr;
            pkt_ctx.dst_addr = ip6->daddr;
            pkt_ctx.protocol = ip6->nexthdr;
        }
    }
    else
        return TC_ACT_UNSPEC;

    if (IPPROTO_TCP != pkt_ctx.protocol)
        return TC_ACT_UNSPEC;

    pkt_ctx.pid = 0;
    pkt_ctx.ingress = ingress;
    pkt_ctx.packet_size = skb->len;
    pkt_ctx.ifindex = skb->ifindex;
    pkt_ctx.timestamp = bpf_ktime_get_ns();

    if (IPPROTO_TCP == pkt_ctx.protocol) {
        if (!skb_revalidate_data(skb, &start, &end, hdr_off_len + sizeof(struct tcphdr)))
            return TC_ACT_UNSPEC;
        struct tcphdr* tcp = (void*)start + hdr_off_len;
        pkt_ctx.src_port = tcp->source;
        pkt_ctx.dst_port = tcp->dest;
    }
    else
        return TC_ACT_UNSPEC;
    
    const size_t pkt_size = sizeof(pkt_ctx);
    bpf_perf_event_output(skb, &net_events, BPF_F_CURRENT_CPU, &pkt_ctx, pkt_size);
    return TC_ACT_UNSPEC;
};

SEC("classifier/ingress")
int classifier_ingress(struct __sk_buff* skb)
{
    if(skb)
        return parse_packet(skb, true);
    return 0;
}

SEC("classifier/egress")
int classifier_egress(struct __sk_buff* skb)
{
    if(skb)
        return parse_packet(skb, false);
    return 0;
}
