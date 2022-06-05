// SPDX-License-Identifier: GPL-2.0
// Based on tcpdrop(8) from BCC by Brendan Gregg
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"
#include "tcpdrop.h"

#define AF_INET    2
#define AF_INET6   10

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

typedef __u64 stack_trace_t[127];

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, stack_trace_t);
} stackmap SEC(".maps");

SEC("kprobe/tcp_drop_reason2.constprop.0")
int BPF_KPROBE(tcp_drop_reason, struct sock *sk, struct sk_buff *skb)
{
	struct event e = {};

	e.pid = 0;
	e.af = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (e.af == AF_INET) {
		e.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		e.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&e.saddr_v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&e.daddr_v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	e.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	e.stackid = bpf_get_stackid(ctx, &stackmap, 0);
	
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
