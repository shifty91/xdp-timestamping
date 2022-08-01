// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022 Linutronix GmbH */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <poll.h>
#include <limits.h>

#include <net/if.h>
#include <netdb.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <xdp/xsk.h>

static struct option long_options[] = {
	{ "interface", optional_argument, NULL, 'i' }, /* default: eth0 */
	{ "queue",     optional_argument, NULL, 'q' }, /* default: 0 */
	{ "duration",  optional_argument, NULL, 'd' }, /* default: 60s */
	{ "help",      no_argument,       NULL, 'h' },
	{ NULL },
};

/* options */
static const char *interface;
static int queue;
static int duration;

/* gobal */
static volatile int stop;

/* xdp */
#define XDP_NUM_FRAMES         (XSK_RING_CONS__DEFAULT_NUM_DESCS + XSK_RING_PROD__DEFAULT_NUM_DESCS)
#define XDP_FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define XDP_BATCH_SIZE         32

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xdpsock {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info umem;
	struct xsk_socket *xsk;
	int fd;
};
static struct xdpsock xsk;

/* statistics */
struct stats {
	uint64_t packets_received;
	uint64_t timestamps_valid;
};
static struct stats current_stats = {
	.packets_received = 0,
	.timestamps_valid = 0,
};

/* meta data */
struct xdp_meta_ts {
	__u64 rx_ts_mono;
	__u64 rx_ts_tai;
} __attribute__((packed));

/* pthread */
static void pthread_err(int ret, const char *msg)
{
	errno = ret;
	perror(msg);
	exit(EXIT_FAILURE);
}

/* stats */
static void update_stats(bool valid)
{
	current_stats.packets_received++;
	if (valid)
		current_stats.timestamps_valid++;
}

/* xdp */
static void xdp_open_socket(const char *interface, int queue)
{
	struct xsk_umem_config cfg = {
		.fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size     = XDP_FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags          = 0,
	};
	int ret, prog_fd, xsks_map = 0, i, fd;
	struct xsk_socket_config xsk_cfg;
	struct bpf_program *prog;
	struct bpf_object *obj;
	unsigned int ifindex;
	struct bpf_map *map;
	void *buffer = NULL;
	uint32_t idx;

	/* Load XDP program */
	obj = bpf_object__open_file("xdp_kern_timestamping.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "bpf_object__open_file() failed\n");
		exit(EXIT_FAILURE);
	}

	prog = bpf_object__next_program(obj, NULL);
	bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "bpf_object__load() failed!\n");
		exit(EXIT_FAILURE);
	}
	prog_fd = bpf_program__fd(prog);

	/* Find xsks_map */
	map = bpf_object__find_map_by_name(obj, "xsks_map");
	xsks_map = bpf_map__fd(map);
	if (xsks_map < 0) {
		fprintf(stderr, "No xsks_map found!\n");
		exit(EXIT_FAILURE);
	}

	ifindex = if_nametoindex(interface);
	if (!ifindex) {
		perror("if_nametoindex() failed!\n");
		exit(EXIT_FAILURE);
	}

	/* Attach */
	ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
	if (ret) {
		fprintf(stderr, "bpf_set_link_xdp_fd() failed!\n");
		exit(EXIT_FAILURE);
	}

	/* Allocate user space memory for xdp frames */
	ret = posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE),
			     XDP_NUM_FRAMES * XDP_FRAME_SIZE);
	if (ret) {
		fprintf(stderr, "posix_memalign() failed!\n");
		exit(EXIT_FAILURE);
	}

	ret = xsk_umem__create(&xsk.umem.umem, buffer,
			       XDP_NUM_FRAMES * XDP_FRAME_SIZE, &xsk.umem.fq,
			       &xsk.umem.cq, &cfg);
	if (ret) {
		fprintf(stderr, "xsk_umem__create() failed!\n");
		exit(EXIT_FAILURE);
	}
	xsk.umem.buffer = buffer;

	/* Add buffers */
	ret = xsk_ring_prod__reserve(&xsk.umem.fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		fprintf(stderr, "xsk_ring_prod__reserve() failed!\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&xsk.umem.fq, idx++) =
			i * XDP_FRAME_SIZE;

	xsk_ring_prod__submit(&xsk.umem.fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	/* Create XDP socket */
	xsk_cfg.rx_size	      = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size	      = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags  = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	xsk_cfg.xdp_flags     = XDP_FLAGS_DRV_MODE;
	xsk_cfg.bind_flags    = 0;
	xsk_cfg.bind_flags   |= XDP_COPY;

	ret = xsk_socket__create(&xsk.xsk, interface,
				 queue, xsk.umem.umem, &xsk.rx,
				 &xsk.tx, &xsk_cfg);
	if (ret) {
		fprintf(stderr, "xsk_socket__create() failed!\n");
		exit(EXIT_FAILURE);
	}

	/* Add xsk into xsks_map */
	fd = xsk_socket__fd(xsk.xsk);
	ret = bpf_map_update_elem(xsks_map, &queue, &fd, 0);
	if (ret) {
		fprintf(stderr, "bpf_map_update_elem() failed!\n");
		exit(EXIT_FAILURE);
	}
}

static void xdp_close_socket(const char *interface)
{
	unsigned int ifindex;

	xsk_socket__delete(xsk.xsk);
	xsk_umem__delete(xsk.umem.umem);

	ifindex = if_nametoindex(interface);
	if (!ifindex) {
		perror("if_nametoindex() failed");
		exit(EXIT_FAILURE);
	}

	bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);

	free(xsk.umem.buffer);
}

#define NSEC_PER_SEC 1000000000ULL

uint64_t ts_to_ns(const struct timespec *ts)
{
	return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

static bool check_timestamps(const char *packet, const struct timespec *now_mono,
			     const struct timespec *now_tai)
{
	static uint64_t prev_rx_ts_tai, prev_rx_ts_mono;
	struct xdp_meta_ts *meta;

	/* Timestamps are stored in front of the packet */
	meta = (struct xdp_meta_ts *)(packet - sizeof(*meta));

#ifdef DEBUG
	printf("tai=%llu now_tai=%lu\n", meta->rx_ts_tai, ts_to_ns(now_tai));
	printf("mono=%llu now_mono=%lu\n", meta->rx_ts_mono, ts_to_ns(now_mono));
#endif

	/* MONO != TAI */
	if (meta->rx_ts_mono == meta->rx_ts_tai)
		return false;

	/* now <= rx ts */
	if (meta->rx_ts_mono > ts_to_ns(now_mono))
		return false;

	if (meta->rx_ts_tai > ts_to_ns(now_tai))
		return false;

	/* MONOTONIC and TAI are moving forward only */
	if (prev_rx_ts_tai > meta->rx_ts_tai)
		return false;

	if (prev_rx_ts_mono > meta->rx_ts_mono)
		return false;

	prev_rx_ts_mono = meta->rx_ts_mono;
	prev_rx_ts_tai = meta->rx_ts_tai;

	return true;
}

static void *xdp_receiver_thread(void *data)
{
	struct pollfd fds[1] = { 0 };

	fds[0].fd = xsk_socket__fd(xsk.xsk);
	fds[0].events = POLLIN;

	while (!stop) {
		uint32_t idx_rx = 0, idx_fq = 0;
		unsigned int received, i;
		struct timespec now_mono;
		struct timespec now_tai;
		uint64_t addr, orig;
		char *packet;
		int ret;

		ret = poll(fds, 1, 1000);
		if (ret == 0)
			continue;
		if (ret < 0) {
			perror("poll() failed");
			return NULL;
		}

		/* Check for received packets */
		received = xsk_ring_cons__peek(&xsk.rx, XDP_BATCH_SIZE, &idx_rx);
		if (!received) {
			if (xsk_ring_prod__needs_wakeup(&xsk.umem.fq))
				recvfrom(xsk_socket__fd(xsk.xsk), NULL, 0,
					 MSG_DONTWAIT, NULL, NULL);
			continue;
		}

		/* Reserve space in fill queue */
		ret = xsk_ring_prod__reserve(&xsk.umem.fq, received, &idx_fq);
		while (ret != received) {
			if (ret < 0) {
				fprintf(stderr, "xsk_ring_prod__reserve() failed!\n");
				return NULL;
			}

			if (xsk_ring_prod__needs_wakeup(&xsk.umem.fq))
				recvfrom(xsk_socket__fd(xsk.xsk), NULL, 0,
					 MSG_DONTWAIT, NULL, NULL);
			ret = xsk_ring_prod__reserve(&xsk.umem.fq, received, &idx_fq);
		}

		/* Get current time */
		ret = clock_gettime(CLOCK_TAI, &now_tai);
		if (ret) {
			fprintf(stderr, "clock_gettime() failed!\n");
			return NULL;
		}

		ret = clock_gettime(CLOCK_MONOTONIC, &now_mono);
		if (ret) {
			fprintf(stderr, "clock_gettime() failed!\n");
			return NULL;
		}

		for (i = 0; i < received; ++i) {
			bool valid;

			/* Get the packet */
			addr = xsk_ring_cons__rx_desc(&xsk.rx, idx_rx)->addr;
			orig = xsk_umem__extract_addr(addr);

			/* Parse it */
			addr = xsk_umem__add_offset_to_addr(addr);
			packet = xsk_umem__get_data(xsk.umem.buffer, addr);

			/* Check timestamps */
			valid = check_timestamps(packet, &now_mono, &now_tai);

			/* Update stats */
			update_stats(valid);

			/* Move buffer back to fill queue */
			*xsk_ring_prod__fill_addr(&xsk.umem.fq, idx_fq++) = orig;
		}

		xsk_ring_prod__submit(&xsk.umem.fq, received);
		xsk_ring_cons__release(&xsk.rx, received);
	}

	return NULL;
}

static void set_default_parameter(void)
{
	interface = "eth0";
	queue	  = 0;
	duration  = 60;
}

static void print_parameter(void)
{
	printf("------------------------------------------\n");
	printf("Interface: %s\n", interface);
	printf("Queue:     %d\n", queue);
	printf("Duration:  %ds\n", duration);
	printf("------------------------------------------\n");
}

static void print_usage_and_die(void)
{
	fprintf(stderr, "usage: xdp_timestamping [options]\n");
	fprintf(stderr, "  -i,--interface:   Network interface\n");
	fprintf(stderr, "  -q,--queue:       Queue to be used for AF_XDP socket\n");
	fprintf(stderr, "  -d,--duration:    Test duration in seconds\n");
	fprintf(stderr, "  -h,--help:        Print this help text\n");

	exit(EXIT_SUCCESS);
}

static void sig_handler(int signal)
{
	stop = 1;
}

static void setup_signals(void)
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;

	if (sigaction(SIGTERM, &sa, NULL)) {
		perror("sigaction() failed");
		exit(EXIT_FAILURE);
	}

	if (sigaction(SIGINT, &sa, NULL)) {
		perror("sigaction() failed");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	struct sched_param param;
	pthread_t recv_thread;
	pthread_attr_t attr;
	int ret, c;

	set_default_parameter();

	while ((c = getopt_long(argc, argv, "hi:q:d:",
				long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			print_usage_and_die();
			break;
		case 'i':
			interface = optarg;
			break;
		case 'q':
			queue = atoi(optarg);
			break;
		case 'd':
			duration = atoi(optarg);
			break;
		default:
			print_usage_and_die();
		}
	}
	if (queue < 0 || duration < 0)
		print_usage_and_die();

	print_parameter();

	ret = pthread_attr_init(&attr);
	if (ret)
		pthread_err(ret, "pthread_attr_init() failed");

	ret = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
	if (ret)
		pthread_err(ret, "pthread_attr_setschedpolicy() failed");

	param.sched_priority = 98;
	ret = pthread_attr_setschedparam(&attr, &param);
	if (ret)
		pthread_err(ret, "pthread_attr_setschedparam() failed");

	ret = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	if (ret)
		pthread_err(ret, "pthread_attr_setinheritsched() failed");

	xdp_open_socket(interface, queue);

	ret = pthread_create(&recv_thread, &attr, xdp_receiver_thread, NULL);
	if (ret)
		pthread_err(ret, "pthread_create() failed");

	setup_signals();

	ret = pthread_setname_np(recv_thread, "XdpTsRx");
	if (ret)
		pthread_err(ret, "pthread_setname_np() failed");

	/* Run test for specified amount of time */
	sleep(duration);
	stop = 1;

	pthread_join(recv_thread, NULL);

	printf("Packets received: %" PRIu64 " Timestamps valid: %" PRIu64 "\n",
	       current_stats.packets_received, current_stats.timestamps_valid);
	printf("------------------------------------------\n");

	xdp_close_socket(interface);

	return current_stats.packets_received == current_stats.timestamps_valid ?
		EXIT_SUCCESS : EXIT_FAILURE;
}
