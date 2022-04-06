/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "hello.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;
const volatile bool trace_failed_only = false;
const volatile bool trace_by_process = true;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

#define MAX_STACK 20

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
	void *buf[MAX_STACK];
	int max_len, ret, n, i = 0;

	max_len = MAX_STACK * sizeof(buf[0]);
	ret = bpf_get_stack(ctx, buf, max_len, 0);
	n = ret / sizeof(buf[0]);

	
	if (i < n) {
		bpf_printk("stack: %pS\n", buf[i++]);
	}
	if (i < n) {
		bpf_printk("     : %pB\n", buf[i++]);
	}
	return 0;
}


