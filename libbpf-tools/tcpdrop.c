// SPDX-License-Identifier: GPL-2.0
// Based on tcpdrop(8) from BCC by Brendan Gregg
#include <sys/resource.h>
#include <arpa/inet.h>
#include <argp.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpdrop.h"
#include "tcpdrop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "map_helpers.h"

static struct env {
	bool ipv4;
	bool ipv6;
	bool verbose;
} env;

static volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "tcpdrop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
	"\nTrace TCP drops by the kernel\n"
	"\n"
	"EXAMPLES:\n"
	"\n"
	"  tcpdrop                    # trace kernel TCP drops\n"
	"  tcpdrop -4                 # trace IPv4 family only\n"
	"  tcpdrop -6                 # trace IPv6 family only\n"
	"\n"
	"OPTIONS:\n"
	;

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 family only" },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 family only" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case '4':
		env.ipv4 = true;
		break;
	case '6':
		env.ipv6 = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

struct ctx {
	int stackmap;
	struct ksyms *ksyms;
};

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct ctx *c = ctx;
	const struct event *e = data;
	const struct ksym *ksym;

	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;
	
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	__u64 ips[127];
	int i;

	if (e->af == AF_INET) {
		s.x4.s_addr = e->saddr_v4;
		d.x4.s_addr = e->daddr_v4;
	} else if (e->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		fprintf(stderr, "broken event: event->af=%d", e->af);
		return;
	}
	
	printf("%-8s %-7d %-2d %-16s:%-6d > %-16s:%-6d %s (%s)\n",
	       "00:00:00",
	       e->pid,
	       e->af == AF_INET ? 4 : 6,
	       inet_ntop(e->af, &s, src, sizeof(src)),
	       ntohs(e->sport),
	       inet_ntop(e->af, &d, dst, sizeof(dst)),
	       ntohs(e->dport),
	       "NULL", "NULL");
	
	if (bpf_map_lookup_elem(c->stackmap, &e->stackid, &ips)) {
		printf("load ips\n");
		return;
	}

	for (i = 0; i < 20 && ips[i]; i++) {
		ksym = ksyms__map_addr(c->ksyms, ips[i]);
		printf("   %llx - %s\n", ips[i], ksym ? ksym->name : "unknown");			
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcpdrop_bpf *obj;
	struct perf_buffer *pb = NULL;
	struct ctx ctx;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		fprintf(stderr, "argp_parse\n");
		return err;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return err;
	}

	obj = tcpdrop_bpf__open_opts(&open_opts);
	if (!obj) {
		err = -errno;
		fprintf(stderr, "failed to open BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpdrop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpdrop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	ctx.stackmap = bpf_map__fd(obj->maps.stackmap);
	if (ctx.stackmap < 0) {
		err = ctx.stackmap;
		fprintf(stderr, "bpf_map__fd(stackmap): %d\n", err);
		goto cleanup;
	}
	
	ctx.ksyms = ksyms__load();
	if (!ctx.ksyms) {
		err = 1;
		fprintf(stderr, "ksyms__load\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 16,
			      handle_event, handle_lost_events, &ctx, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = 1;
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("%-8s %-7s %-2s %-20s > %-20s %s (%s)\n",
	       "TIME", "PID", "IP", "SADDR:SPORT", "DADDR:DPORT", "STATE", "FLAGS");
	
	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "perf_buffer__poll: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	cleanup_core_btf(&open_opts);
	tcpdrop_bpf__destroy(obj);
	perf_buffer__free(pb);
	ksyms__free(ctx.ksyms);

	return err != 0;
}
