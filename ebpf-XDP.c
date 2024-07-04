#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp_openvpn_filter")
int xdp_openvpn_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct udphdr *udp = (struct udphdr *)((__u32 *)ip + ip->ihl);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP) || ip->protocol != IPPROTO_UDP || ntohs(udp->dest) != 1194)
        return XDP_DROP; // Drop UDP packets not destined for port 1194

    // Check for OpenVPN characteristics
    if (data + 45 >= data_end || udp->len < 47)
        return XDP_DROP; // Drop packet too short to contain OpenVPN header

    __u8 *udp_data = (__u8 *)(udp) + sizeof(struct udphdr);
    if (udp_data[8] != 0x38 || *((__u32 *)(udp_data + 37)) != 0x00000001 ||
        udp_data[45] != 0x00 || *((__u32 *)(udp_data + 46)) != 0x00000000)
        return XDP_DROP; // Drop packets not matching OpenVPN expression

    // Allow the packet
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
