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

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
	void* buf[12];
	long ret;
	
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	
	ret = bpf_get_task_stack(task, buf, 12, 0);
	bpf_printk("HELLO %d.\n", ret);
	return 0;
}


