// SPDX-License-Identifier: GPL-2.0
#ifndef __TCPDROP_H
#define __TCPDROP_H

struct event {
	__u32 pid;
	__u32 af;
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	__u16 sport;
	__u16 dport;

	__u32 stackid;
};

#endif /* __TCPDROP_H */
