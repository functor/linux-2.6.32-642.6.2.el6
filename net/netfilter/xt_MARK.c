/*
 *	xt_MARK - Netfilter module to modify the NFMARK field of an skb
 *
 *	(C) 1999-2001 Marc Boucher <marc@mbsi.ca>
 *	Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *	Jan Engelhardt <jengelh@computergmbh.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/udp.h>
#include <net/checksum.h>
#include <net/route.h>
#include <net/inet_hashtables.h>
#include <net/net_namespace.h>

#include <net/netfilter/nf_conntrack.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_MARK.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marc Boucher <marc@mbsi.ca>");
MODULE_DESCRIPTION("Xtables: packet mark modification");
MODULE_ALIAS("ipt_MARK");
MODULE_ALIAS("ip6t_MARK");

DECLARE_PER_CPU(int, sknid_elevator);

#define PEERCRED_SET(x) ((x!=0) && (x!=(unsigned int)-1))

static inline u_int16_t get_dst_port(struct nf_conntrack_tuple *tuple)
{
	switch (tuple->dst.protonum) {
	case IPPROTO_GRE:
		/* XXX Truncate 32-bit GRE key to 16 bits */
		return tuple->dst.u.gre.key;
	case IPPROTO_ICMP:
		/* Bind on ICMP echo ID */
		return tuple->src.u.icmp.id;
	case IPPROTO_TCP:
		return tuple->dst.u.tcp.port;
	case IPPROTO_UDP:
		return tuple->dst.u.udp.port;
	default:
		return tuple->dst.u.all;
	}
}

static inline u_int16_t get_src_port(struct nf_conntrack_tuple *tuple)
{
	switch (tuple->dst.protonum) {
	case IPPROTO_GRE:
		/* XXX Truncate 32-bit GRE key to 16 bits */
		return htons(ntohl(tuple->src.u.gre.key));
	case IPPROTO_ICMP:
		/* Bind on ICMP echo ID */
		return tuple->src.u.icmp.id;
	case IPPROTO_TCP:
		return tuple->src.u.tcp.port;
	case IPPROTO_UDP:
		return tuple->src.u.udp.port;
	default:
		return tuple->src.u.all;
	}
}

static struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr,
				      __be16 sport, __be32 daddr, __be16 dport,
				      int dif, struct udp_table *udptable)
{
	struct sock *sk, *result = NULL;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(dport);
	unsigned int hash = udp_hashfn(net, hnum);
	struct udp_hslot *hslot = &udptable->hash[hash];
	int badness = -1;

	rcu_read_lock();
	sk_nulls_for_each_rcu(sk, node, &hslot->head) {
		struct inet_sock *inet = inet_sk(sk);

		if (net_eq(sock_net(sk), net) && sk->sk_hash == hnum &&
		    !ipv6_only_sock(sk)) {
			int score = (sk->sk_family == PF_INET ? 1 : 0);

			if (inet->rcv_saddr) {
				if (inet->rcv_saddr != daddr)
					continue;
				score += 2;
			} else {
				/* block non nx_info ips */
				if (!v4_addr_in_nx_info(sk->sk_nx_info,
							daddr, NXA_MASK_BIND))
					continue;
			}
			if (inet->daddr) {
				if (inet->daddr != saddr)
					continue;
				score += 2;
			}
			if (inet->dport) {
				if (inet->dport != sport)
					continue;
				score += 2;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score += 2;
			}
			if (score == 9) {
				result = sk;
				break;
			} else if (score > badness) {
				result = sk;
				badness = score;
			}
		}
	}

	if (result)
		sock_hold(result);
	rcu_read_unlock();
	return result;
}

int onceonly = 1;

static unsigned int
mark_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
	const struct xt_mark_tginfo2 *info = par->targinfo;
	long mark = -1;
	enum ip_conntrack_info ctinfo;
	struct sock *connection_sk;
	int dif;
	struct nf_conn *ct;
	extern struct inet_hashinfo tcp_hashinfo;
	enum ip_conntrack_dir dir;
	int *curtag;
	u_int32_t src_ip;
	u_int32_t dst_ip;
	u_int16_t proto, src_port;
	u_int32_t ip;
	u_int16_t port;

	if (info->mark == ~0U) {
		// As of 2.6.27.39, Dec 8 2009, 
		// NetNS + VNET = Trouble
		// Let's handle this as a special case
		struct net *net = dev_net(skb->dev);
		if (!net_eq(net, &init_net)) {
			WARN_ON(onceonly);
			onceonly = 0;
			return XT_CONTINUE;
		}

		/* copy-xid */
		dif = ((struct rtable *)(skb_dst(skb)))->rt_iif;

		ct = nf_ct_get(skb, &ctinfo);
		if (!ct)
			goto out_mark_finish;

		dir = CTINFO2DIR(ctinfo);
		src_ip = ct->tuplehash[dir].tuple.src.u3.ip;
		dst_ip = ct->tuplehash[dir].tuple.dst.u3.ip;
		src_port = get_src_port(&ct->tuplehash[dir].tuple);
		proto = ct->tuplehash[dir].tuple.dst.protonum;

		ip = ct->tuplehash[dir].tuple.dst.u3.ip;
		port = get_dst_port(&ct->tuplehash[dir].tuple);

		if (proto == 1) {
			if (skb->mark > 0)
				/* The packet is marked, it's going out */
				ct->xid[0] = skb->mark;

			if (ct->xid[0] > 0)
				mark = ct->xid[0];
		} else if (proto == 17) {
			struct sock *sk;
			if (!skb->mark) {
				sk = __udp4_lib_lookup(net, src_ip, src_port,
						       ip, port, dif, &udp_table);

				if (sk && par->hooknum == NF_INET_LOCAL_IN)
					mark = sk->sk_nid;

				if (sk)
					sock_put(sk);
			} else if (skb->mark > 0)
				/* The packet is marked, it's going out */
				ct->xid[0] = skb->mark;
		} else if (proto == 6) {	/* TCP */
			int sockettype = 0;	/* Established socket */

			/* Looks for an established socket or a listening 
			   socket corresponding to the 4-tuple, in that order.
			   The order is important for Codemux connections
			   to be handled properly */

			connection_sk = inet_lookup_established(net,
								&tcp_hashinfo,
								src_ip,
								src_port, ip,
								port, dif);

			if (!connection_sk) {
				connection_sk = inet_lookup_listener(net,
								     &tcp_hashinfo,
								     ip, port,
								     dif);
				sockettype = 1;	/* Listening socket */
			}

			if (connection_sk) {
				if (connection_sk->sk_state == TCP_TIME_WAIT) {
					inet_twsk_put(inet_twsk(connection_sk));
					goto out_mark_finish;
				}

				/* The peercred is not set. We set it if the other side has an xid. */
				if (!PEERCRED_SET
				    (connection_sk->sk_peercred.uid)
				    && ct->xid[!dir] > 0 && (sockettype == 0)) {
					connection_sk->sk_peercred.gid =
					    connection_sk->sk_peercred.uid =
					    ct->xid[!dir];
				}

				/* The peercred is set, and is not equal to the XID of 'the other side' */
				else if (PEERCRED_SET
					 (connection_sk->sk_peercred.uid)
					 && (connection_sk->sk_peercred.uid !=
					     ct->xid[!dir])
					 && (sockettype == 0)) {
					mark = connection_sk->sk_peercred.uid;
				}

				/* Has this connection already been tagged? */
				if (ct->xid[dir] < 1) {
					/* No - let's tag it */
					ct->xid[dir] = connection_sk->sk_nid;
				}

				if (mark == -1 && (ct->xid[dir] != 0))
					mark = ct->xid[dir];

				sock_put(connection_sk);
			}

			/* All else failed. Is this a connection over raw sockets?
			   That explains why we couldn't get anything out of skb->sk,
			   or look up a "real" connection. */
			if (ct->xid[dir] < 1) {
				if (skb->skb_tag)
					ct->xid[dir] = skb->skb_tag;
			}

			/* Covers CoDemux case */
			if (mark < 1 && (ct->xid[dir] > 0))
				mark = ct->xid[dir];

			if (mark < 1 && (ct->xid[!dir] > 0))
				mark = ct->xid[!dir];
			goto out_mark_finish;
		}
	} else
		mark = (skb->mark & ~info->mask) ^ info->mark;

out_mark_finish:
	if (mark != -1)
		skb->mark = mark;

	curtag = &__get_cpu_var(sknid_elevator);
	if (mark > 0 && *curtag == -2 && par->hooknum == NF_INET_LOCAL_IN)
		*curtag = mark;

	return XT_CONTINUE;
}

static struct xt_target mark_tg_reg __read_mostly = {
	.name = "MARK",
	.revision = 2,
	.family = NFPROTO_UNSPEC,
	.target = mark_tg,
	.targetsize = sizeof(struct xt_mark_tginfo2),
	.me = THIS_MODULE,
};

static int __init mark_tg_init(void)
{
	return xt_register_target(&mark_tg_reg);
}

static void __exit mark_tg_exit(void)
{
	xt_unregister_target(&mark_tg_reg);
}

module_init(mark_tg_init);
module_exit(mark_tg_exit);
