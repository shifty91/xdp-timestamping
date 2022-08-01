// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022 Linutronix GmbH */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#define MAX_AF_SOCKS	128

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_AF_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct xdp_meta_ts {
	__u64 rx_ts_mono;
	__u64 rx_ts_tai;
} __attribute__((aligned(4))) __attribute__((packed));

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int idx = ctx->rx_queue_index;
	struct xdp_meta_ts *meta;
	void *data;
	int ret;

	/* Reserve space in front of the packet */
	ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (ret)
		return XDP_ABORTED;

	meta = (void *)(unsigned long)ctx->data_meta;
	data = (void *)(unsigned long)ctx->data;
	if ((void *)(meta + 1) > data)
		return XDP_ABORTED;

	/* Save timestamps in meta area */
	meta->rx_ts_mono = bpf_ktime_get_ns();
	meta->rx_ts_tai = bpf_ktime_get_tai_ns();

	/* Redirect to user space */
	if (bpf_map_lookup_elem(&xsks_map, &idx))
		return bpf_redirect_map(&xsks_map, idx, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
