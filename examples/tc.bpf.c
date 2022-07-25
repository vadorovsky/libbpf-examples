// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <asm/types.h>
#include <asm/byteorder.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// #define BUF_CAPACITY 9198
#define BUF_CAPACITY 256
#define SMALL_BUF_CAPACITY 64
#define X_FORWARDED_FOR_LEN 17
#define IP_MAX_LEN 15
#define BYTE_DIGIT_ZERO 48
#define BYTE_DIGIT_NINE 57
#define BYTE_DOT 46
#define U32_MAX 4294967295
#define U8_MAX 255

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u8 X_FORWARDED_FOR[] = { 88,	45,  70, 111, 114, 119, 97, 114, 100,
			   101, 100, 45, 70,  111, 114, 58, 32 };
__u8 IP[] = { 49, 57, 50, 46, 49, 54, 56, 46, 49, 50, 51, 46, 50, 53, 53 };
__u32 ifindex = 0;

struct buf {
	__u8 data[BUF_CAPACITY];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct buf);
} buf_array SEC(".maps");

SEC("classifier")
int tc_bytes(struct __sk_buff *skb)
{
	// bpf_printk("tc_bytes: received packet\n");

	__u32 key = 0;
	struct buf *buf = bpf_map_lookup_elem(&buf_array, &key);
	if (!buf)
		return 0;

	if (skb->protocol == __constant_htons(ETH_P_IP))
		return 0;

	int offset = BPF_LL_OFF + ETH_HLEN;

	struct iphdr iphdr;
	int err = bpf_skb_load_bytes(skb, offset, &iphdr, sizeof(iphdr));
	if (err != 0)
		return 0;

	if (iphdr.protocol != IPPROTO_TCP)
		return 0;

	offset += sizeof(struct iphdr) + sizeof(struct tcphdr);

	// __u32 len = skb->len - offset;
	// if (len > BUF_CAPACITY)
	// 	len = BUF_CAPACITY;

	// __u32 len = BUF_CAPACITY;
	// __u32 skb_len = skb->len - offset;
	// if (skb_len < len)
	// 	len = skb_len;

	err = bpf_skb_load_bytes(skb, offset, buf->data, BUF_CAPACITY);
	if (err != 0)
		return 0;

	__u8 found = 0;
	__u32 position;
	int i;
	for (i = 0; i + X_FORWARDED_FOR_LEN < BUF_CAPACITY; i++) {
		if (buf->data[i] != X_FORWARDED_FOR[0])
			continue;
		if (buf->data[i + 1] != X_FORWARDED_FOR[1])
			continue;
		if (buf->data[i + 2] != X_FORWARDED_FOR[2])
			continue;
		if (buf->data[i + 3] != X_FORWARDED_FOR[3])
			continue;
		if (buf->data[i + 4] != X_FORWARDED_FOR[4])
			continue;
		if (buf->data[i + 5] != X_FORWARDED_FOR[5])
			continue;
		if (buf->data[i + 6] != X_FORWARDED_FOR[6])
			continue;
		if (buf->data[i + 7] != X_FORWARDED_FOR[7])
			continue;
		if (buf->data[i + 8] != X_FORWARDED_FOR[8])
			continue;
		if (buf->data[i + 9] != X_FORWARDED_FOR[9])
			continue;
		if (buf->data[i + 10] != X_FORWARDED_FOR[10])
			continue;
		if (buf->data[i + 11] != X_FORWARDED_FOR[11])
			continue;
		if (buf->data[i + 12] != X_FORWARDED_FOR[12])
			continue;
		if (buf->data[i + 13] != X_FORWARDED_FOR[13])
			continue;
		if (buf->data[i + 14] != X_FORWARDED_FOR[14])
			continue;
		if (buf->data[i + 15] != X_FORWARDED_FOR[15])
			continue;
		if (buf->data[i + 16] != X_FORWARDED_FOR[16])
			continue;
		found = 1;
		position = i + X_FORWARDED_FOR_LEN;
		break;
	}

	if (found)
		bpf_printk("found X-Forwarded-For\n");

	__u32 ip;
	__u8 octet;
	for (i = 0; i < IP_MAX_LEN; i++) {
		i += position;
		if (i >= BUF_CAPACITY)
			return 0;
		__u8 c = IP[i];
		if (c >= BYTE_DIGIT_ZERO && c <= BYTE_DIGIT_NINE) {
			if (octet > U8_MAX)
				return 0;
			__u8 prev_int = octet * 10;
			if (prev_int > U8_MAX)
				return 0;
			__u8 cur_int = c - BYTE_DIGIT_ZERO;
			if (cur_int > U8_MAX)
				return 0;
			octet = prev_int + cur_int;
			if (octet > U8_MAX)
				return 0;
		} else if (c == BYTE_DOT) {
			if (ip > U32_MAX)
				return 0;
			__u32 prev_octets = ip << 8;
			if (prev_octets > U32_MAX)
				return 0;
			ip = prev_octets + octet;
			if (ip > U32_MAX)
				return 0;
			octet = 0;
		} else {
			if (ip > U32_MAX)
				return 0;
			__u32 prev_octets = ip << 8;
			if (prev_octets > U32_MAX)
				return 0;
			ip = prev_octets + octet;
			if (ip > U32_MAX)
				return 0;
			break;
		}
	}

	bpf_printk("ip: %d\n", ip);

	return 0;
}
