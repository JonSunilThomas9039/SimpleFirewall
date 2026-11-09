#include<linux/types.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include<bpf/bpf_helpers.h>
#include<linux/ip.h>
#include<linux/if_ether.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/in.h>

// struct storing the blacklist of ips
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key,__u32);
	__type(value,__u32);
} ip_blacklist SEC (".maps");

// struct storing the whitelist of ports
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key,__be16);
	__type(value,__be16);
} port_whitelist SEC(".maps");


SEC("xdp")
int verify_packet(struct xdp_md *ctx){
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;

	struct ethhdr *start = data;
	struct iphdr *ipstart = (void*)(long)(start+1);

	if ((void*)(start+1) > data_end){
		return XDP_DROP;
	}
	if ((void*)(ipstart+1) > data_end){
		return XDP_DROP;
	}
	if (ipstart->protocol == IPPROTO_ICMP){
		return XDP_DROP;
	}

	if ((void*)bpf_map_lookup_elem(&ip_blacklist,&(ipstart->saddr))!=NULL){
		return XDP_DROP;
	}

	if (ipstart->protocol == IPPROTO_TCP){
		struct tcphdr *tcp = (void*)(long)(ipstart+1);
		if ((void*)(tcp+1)>data_end || (void*) bpf_map_lookup_elem(&port_whitelist,&(tcp->dest)) == NULL){
			return XDP_DROP;
		}
	}
	if (ipstart->protocol == IPPROTO_UDP){
		struct udphdr *udp = (void*)(long)(ipstart+1);
		if ((void*)(udp+1)>data_end || (void*) bpf_map_lookup_elem(&port_whitelist,&(udp->dest)) == NULL){
			return XDP_DROP;
		}
	}
	return XDP_PASS;
};
char _license[] SEC("license")="GPL";
