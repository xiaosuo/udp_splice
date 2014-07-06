/**
 * udp_splice - Splice two UDP sockets.
 * Copyright (C) 2013 Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "udp_splice.h"

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/proc_fs.h>

#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <net/genetlink.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Splice two UDP Sockets");
MODULE_ALIAS_GENL_FAMILY(UDP_SPLICE_GENL_NAME);

struct udp_splice_tuple {
	unsigned int	hash;
	__be32		laddr, raddr;
	__be16		lport, rport;
};

struct udp_splice_ep {
	struct udp_splice_tuple	tuple;
	int			idx;
	spinlock_t		lock;
	u64			rx_packets;
	u64			rx_bytes;
	struct rb_node		node;
};

struct udp_splice_entry {
	struct udp_splice_ep	ep[2];
	atomic_t		ref;
	u32			portid;

	struct timer_list	timer;
	unsigned long		timeout;
	unsigned long		last_used;
};

static DEFINE_SPINLOCK(udp_splice_hash_table_lock);
static struct rb_root	*udp_splice_hash_table;

static unsigned int	udp_splice_hash_table_size;

static struct rb_root *udp_splice_alloc_hash_table(unsigned int *psize)
{
	unsigned long size;
	struct rb_root *hash_table;

	*psize = roundup(*psize, PAGE_SIZE / sizeof(*hash_table));
	size = (*psize) * sizeof(*hash_table);
	hash_table = (void *)__get_free_pages(GFP_KERNEL | __GFP_NOWARN |
			__GFP_ZERO, get_order(size));
	if (!hash_table) {
		pr_warn("Falling back to vzalloc\n");
		hash_table = vzalloc(size);
	}

	return hash_table;
}

static void udp_splice_free_hash_table(struct rb_root *hash_table,
		unsigned int size)
{
	if (is_vmalloc_addr(hash_table))
		vfree(hash_table);
	else
		free_pages((unsigned long)hash_table,
				get_order(sizeof(*hash_table) * size));
}

static inline struct udp_splice_entry *udp_splice_ep2entry(
		struct udp_splice_ep *ep)
{
	return container_of(ep, struct udp_splice_entry, ep[ep->idx]);
}

static inline void udp_splice_hash(struct udp_splice_tuple *tuple)
{
	tuple->hash = ntohl(tuple->laddr) ^ ntohl(tuple->raddr) ^
		ntohs(tuple->lport) ^ ntohs(tuple->rport);
}

static inline int udp_splice_cmp_tuple(const struct udp_splice_tuple *tuple,
		const struct udp_splice_tuple *tuple2)
{
	return memcmp(tuple, tuple2, sizeof(*tuple));
}

static void __udp_splice_insert_ep(struct udp_splice_ep *ep,
		struct rb_root *hash_table, unsigned int hash_table_size)
{
	struct rb_node **new, *parent = NULL;
	struct rb_root *root;

	root = &hash_table[ep->tuple.hash % hash_table_size];
	new = &root->rb_node;
	while (*new) {
		struct udp_splice_ep *this;
		int rc;

		parent = *new;
		this = rb_entry(parent, struct udp_splice_ep, node);
		rc = udp_splice_cmp_tuple(&ep->tuple, &this->tuple);
		if (rc < 0)
			new = &parent->rb_left;
		else if (rc > 0)
			new = &parent->rb_right;
		else
			BUG_ON(true);
	}

	rb_link_node(&ep->node, parent, new);
	rb_insert_color(&ep->node, root);
}

static void udp_splice_insert_ep(struct udp_splice_ep *ep)
{
	__udp_splice_insert_ep(ep, udp_splice_hash_table,
			udp_splice_hash_table_size);
}

static inline void __udp_splice_unlink_entry(struct udp_splice_entry *entry)
{
	rb_erase(&entry->ep[0].node, &udp_splice_hash_table[entry->ep[0].tuple.hash % udp_splice_hash_table_size]);
	rb_erase(&entry->ep[1].node, &udp_splice_hash_table[entry->ep[1].tuple.hash % udp_splice_hash_table_size]);
}

static int udp_splice_set_hash_table_size(const char *val,
		struct kernel_param *kp)
{
	unsigned int hash_table_size, i;
	struct rb_root *hash_table;
	int retval;
	struct udp_splice_ep *ep;
	struct udp_splice_entry *entry;
	struct rb_node *node;

	if (!net_eq(current->nsproxy->net_ns, &init_net))
		return -EOPNOTSUPP;
	if (!udp_splice_hash_table_size)
		return param_set_uint(val, kp);
	retval = kstrtouint(val, 0, &hash_table_size);
	if (retval)
		return retval;
	if (!hash_table_size)
		return -EINVAL;

	hash_table = udp_splice_alloc_hash_table(&hash_table_size);
	if (!hash_table)
		return -ENOMEM;

	spin_lock_bh(&udp_splice_hash_table_lock);
	if (hash_table_size != udp_splice_hash_table_size) {
		for (i = 0; i < udp_splice_hash_table_size; i++) {
			while ((node = udp_splice_hash_table[i].rb_node)) {
				ep = rb_entry(node, struct udp_splice_ep,
						node);
				entry = udp_splice_ep2entry(ep);
				__udp_splice_unlink_entry(entry);
				__udp_splice_insert_ep(&entry->ep[0],
						hash_table, hash_table_size);
				__udp_splice_insert_ep(&entry->ep[1],
						hash_table, hash_table_size);
			}
		}
		swap(hash_table, udp_splice_hash_table);
		swap(hash_table_size, udp_splice_hash_table_size);
		pr_info("set the size of the hash table to %u\n",
				udp_splice_hash_table_size);
	}
	spin_unlock_bh(&udp_splice_hash_table_lock);

	udp_splice_free_hash_table(hash_table, hash_table_size);

	return 0;
}

module_param_call(hash_table_size, udp_splice_set_hash_table_size,
		param_get_uint, &udp_splice_hash_table_size, 0644);
MODULE_PARM_DESC(hash_table_size,
		"size of the hash table for UDP splice entries");

static unsigned int		udp_splice_default_timeout = 180;

static int udp_splice_set_default_timeout(const char *val,
		struct kernel_param *kp)
{
	unsigned int timeout;
	int retval;

	if (!net_eq(current->nsproxy->net_ns, &init_net))
		return -EOPNOTSUPP;
	retval = kstrtouint(val, 0, &timeout);
	if (retval)
		return retval;
	if (!timeout)
		return -EINVAL;
	udp_splice_default_timeout = timeout;

	return 0;
}

module_param_call(default_timeout, udp_splice_set_default_timeout,
		param_get_uint, &udp_splice_default_timeout, 0644);
MODULE_PARM_DESC(default_timeout,
		"default timeout of UDP splice entries in second");

static struct nf_hook_ops udp_splice_hook_ops __read_mostly;

static struct udp_splice_ep *__udp_splice_find_ep(
		const struct udp_splice_tuple *tuple)
{
	struct udp_splice_ep *ep;
	struct rb_root *root;
	struct rb_node *node;
	int rc;

	root = &udp_splice_hash_table[tuple->hash % udp_splice_hash_table_size];
	node = root->rb_node;
	while (node) {
		ep = rb_entry(node, struct udp_splice_ep, node);
		rc = udp_splice_cmp_tuple(tuple, &ep->tuple);
		if (rc < 0)
			node = node->rb_left;
		else if (rc > 0)
			node = node->rb_right;
		else
			return ep;
	}

	return NULL;
}

static struct udp_splice_entry *udp_splice_find_entry(
		const struct udp_splice_tuple *tuple, int *idx)
{
	struct udp_splice_ep *ep;
	struct udp_splice_entry *entry = NULL;

	spin_lock_bh(&udp_splice_hash_table_lock);
	ep = __udp_splice_find_ep(tuple);
	if (ep) {
		entry = udp_splice_ep2entry(ep);
		atomic_inc(&entry->ref);
		if (idx)
			*idx = ep->idx;
	}
	spin_unlock_bh(&udp_splice_hash_table_lock);

	return entry;
}

static void udp_splice_put_entry(struct udp_splice_entry *entry)
{
	if (atomic_dec_and_test(&entry->ref))
		kfree(entry);
}

static struct genl_family udp_splice_family = {
	.id		= GENL_ID_GENERATE,
	.name		= UDP_SPLICE_GENL_NAME,
	.version	= UDP_SPLICE_GENL_VERSION,
	.maxattr	= UDP_SPLICE_ATTR_MAX,
};

/* Copied from linux. */
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct file *file;
	struct socket *sock;

	*err = -EBADF;
	file = fget_light(fd, fput_needed);
	if (file) {
		sock = sock_from_file(file, err);
		if (sock)
			return sock;
		fput_light(file, *fput_needed);
	}
	return NULL;
}

/* Copied from sys_getsockname */
static int udp_splice_get_name(int socket, struct sockaddr *addr, int *plen,
		int peer)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int error, fput_needed, len;

	sock = sockfd_lookup_light(socket, &error, &fput_needed);
	if (!sock)
		goto out;

	if (!sock->sk || sock->sk->sk_protocol != IPPROTO_UDP ||
	    sock->sk->sk_state != TCP_ESTABLISHED) {
		error = -EINVAL;
		goto out;
	}

	/**
	 * XXX: we don't call security_socket_get{sock,peer}name() as they
	 * are NOT exported. In fact, I think it isn't necessary, since
	 * we own the socket.
	 */

	error = sock->ops->getname(sock, (struct sockaddr *)&address, &len,
			peer);
	if (error)
		goto out_put;
	if (len > *plen) {
		error = -EINVAL;
		goto out_put;
	}
	memcpy(addr, &address, len);
	*plen = len;
out_put:
	fput_light(sock->file, fput_needed);
out:
	return error;
}

static int udp_splice_get_tuple(struct udp_splice_tuple *tuple, u32 sock)
{
	struct sockaddr_in addr;
	int len = sizeof(addr);
	int retval;

	retval = udp_splice_get_name(sock, (struct sockaddr *)&addr, &len, 0);
	if (retval)
		goto err;
	if (addr.sin_family != AF_INET) {
		retval = -EINVAL;
		goto err;
	}
	tuple->laddr = addr.sin_addr.s_addr;
	tuple->lport = addr.sin_port;

	retval = udp_splice_get_name(sock, (struct sockaddr *)&addr, &len, 1);
	if (retval)
		goto err;
	if (addr.sin_family != AF_INET) {
		retval = -EINVAL;
		goto err;
	}
	tuple->raddr = addr.sin_addr.s_addr;
	tuple->rport = addr.sin_port;
	udp_splice_hash(tuple);
err:
	return retval;
}

static inline void udp_splice_unlink_entry(struct udp_splice_entry *entry)
{
	spin_lock_bh(&udp_splice_hash_table_lock);
	__udp_splice_unlink_entry(entry);
	spin_unlock_bh(&udp_splice_hash_table_lock);
}

static void udp_splice_timedout_entry(unsigned long _entry)
{
	struct udp_splice_entry *entry = (struct udp_splice_entry *)_entry;

	if (time_before(jiffies, entry->last_used + entry->timeout)) {
		entry->timer.expires = entry->last_used + entry->timeout;
		add_timer(&entry->timer);
		return;
	}
	udp_splice_unlink_entry(entry);
	udp_splice_put_entry(entry);
}

static int udp_splice_cmd_add(struct sk_buff *skb, struct genl_info *info)
{
	struct udp_splice_tuple tuple, tuple2;
	int retval;
	struct udp_splice_entry *entry;
	u32 sock, sock2;

	if (current->nsproxy->net_ns != &init_net) {
		retval = -EOPNOTSUPP;
		goto err;
	}

	if (!info->attrs[UDP_SPLICE_ATTR_SOCK] ||
	    !info->attrs[UDP_SPLICE_ATTR_SOCK2] ||
	    (info->attrs[UDP_SPLICE_ATTR_TIMEOUT] &&
	     !nla_get_u32(info->attrs[UDP_SPLICE_ATTR_TIMEOUT]))) {
		retval = -EINVAL;
		goto err;
	}

	sock = nla_get_u32(info->attrs[UDP_SPLICE_ATTR_SOCK]);
	sock2 = nla_get_u32(info->attrs[UDP_SPLICE_ATTR_SOCK2]);
	if (sock == sock2) {
		retval = -EINVAL;
		goto err;
	}
	retval = udp_splice_get_tuple(&tuple, sock);
	if (retval)
		goto err;
	retval = udp_splice_get_tuple(&tuple2, sock2);
	if (retval)
		goto err;
	if (memcmp(&tuple, &tuple2, sizeof(tuple)) == 0) {
		retval = -EINVAL;
		goto err;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		retval = -ENOMEM;
		goto err;
	}
	entry->ep[0].tuple = tuple;
	entry->ep[0].idx = 0;
	spin_lock_init(&entry->ep[0].lock);
	entry->ep[1].tuple = tuple2;
	entry->ep[1].idx = 1;
	spin_lock_init(&entry->ep[1].lock);
	entry->portid = info->snd_portid;
	setup_timer(&entry->timer, udp_splice_timedout_entry,
			(unsigned long)entry);
	if (info->attrs[UDP_SPLICE_ATTR_TIMEOUT])
		entry->timeout = nla_get_u32(info->attrs[UDP_SPLICE_ATTR_TIMEOUT]);
	else
		entry->timeout = udp_splice_default_timeout;
	entry->timeout *= HZ;

	spin_lock_bh(&udp_splice_hash_table_lock);
	if (__udp_splice_find_ep(&tuple) || __udp_splice_find_ep(&tuple2)) {
		retval = -EEXIST;
		goto err2;
	}
	atomic_set(&entry->ref, 1);
	udp_splice_insert_ep(&entry->ep[0]);
	udp_splice_insert_ep(&entry->ep[1]);
	entry->last_used = jiffies;
	entry->timer.expires = entry->last_used + entry->timeout;
	add_timer(&entry->timer);
	spin_unlock_bh(&udp_splice_hash_table_lock);

	return 0;
err2:
	spin_unlock_bh(&udp_splice_hash_table_lock);
	kfree(entry);
err:
	return retval;
}

static int udp_splice_get_tuple_from_genl(struct udp_splice_tuple *tuple,
		struct genl_info *info)
{
	u32 sock;
	int retval;

	if (info->attrs[UDP_SPLICE_ATTR_SOCK]) {
		sock = nla_get_u32(info->attrs[UDP_SPLICE_ATTR_SOCK]);
	} else if (info->attrs[UDP_SPLICE_ATTR_SOCK2]) {
		sock = nla_get_u32(info->attrs[UDP_SPLICE_ATTR_SOCK2]);
	} else {
		retval = -EINVAL;
		goto err;
	}
	retval = udp_splice_get_tuple(tuple, sock);
err:
	return retval;
}

static int udp_splice_cmd_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct udp_splice_tuple tuple;
	int retval;
	struct udp_splice_ep *ep;
	struct udp_splice_entry *entry = NULL;

	if (current->nsproxy->net_ns != &init_net) {
		retval = -EOPNOTSUPP;
		goto err;
	}

	retval = udp_splice_get_tuple_from_genl(&tuple, info);
	if (retval)
		goto err;
	spin_lock_bh(&udp_splice_hash_table_lock);
	ep = __udp_splice_find_ep(&tuple);
	if (ep) {
		entry = udp_splice_ep2entry(ep);
		atomic_inc(&entry->ref);
	}
	spin_unlock_bh(&udp_splice_hash_table_lock);

	if (entry) {
		if (del_timer_sync(&entry->timer)) {
			udp_splice_unlink_entry(entry);
			udp_splice_put_entry(entry);
		}
		udp_splice_put_entry(entry);
	} else {
		retval = -ENOENT;
	}
err:
	return retval;
}

static int udp_splice_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct udp_splice_tuple tuple;
	int retval;

	if (current->nsproxy->net_ns != &init_net) {
		retval = -EOPNOTSUPP;
		goto err;
	}

	retval = udp_splice_get_tuple_from_genl(&tuple, info);
	if (retval)
		goto err;
	spin_lock_bh(&udp_splice_hash_table_lock);
	if (__udp_splice_find_ep(&tuple))
		retval = 0;
	else
		retval = -ENOENT;
	spin_unlock_bh(&udp_splice_hash_table_lock);
err:
	return retval;
}

static struct nla_policy udp_splice_policy[UDP_SPLICE_ATTR_MAX + 1] = {
	[UDP_SPLICE_ATTR_SOCK]		= { .type = NLA_U32, },
	[UDP_SPLICE_ATTR_SOCK2]		= { .type = NLA_U32, },
	[UDP_SPLICE_ATTR_TIMEOUT]	= { .type = NLA_U32, },
};

static struct genl_ops udp_splice_ops[] = {
	{
		.cmd	= UDP_SPLICE_CMD_ADD,
		.doit	= udp_splice_cmd_add,
		.policy	= udp_splice_policy,
	},
	{
		.cmd	= UDP_SPLICE_CMD_DELETE,
		.doit	= udp_splice_cmd_delete,
		.policy	= udp_splice_policy,
	},
	{
		.cmd	= UDP_SPLICE_CMD_GET,
		.doit	= udp_splice_cmd_get,
		.policy	= udp_splice_policy,
	},
};

static DEFINE_MUTEX(udp_splice_register_lock);
static bool udp_splice_register = true;

static void udp_splice_register_hook(struct work_struct *w)
{
	mutex_lock(&udp_splice_register_lock);
	if (udp_splice_register) {
		if (!list_empty(&udp_splice_hook_ops.list)) {
			nf_unregister_hook(&udp_splice_hook_ops);
			INIT_LIST_HEAD(&udp_splice_hook_ops.list);
		}
		if (nf_register_hook(&udp_splice_hook_ops))
			pr_err("Failed to register the netfilter hook again\n");
	}
	mutex_unlock(&udp_splice_register_lock);
}

static DECLARE_WORK(udp_splice_register_hook_work, udp_splice_register_hook);

static unsigned int udp_splice_hook(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
		const struct nf_hook_ops *ops,
#else
		unsigned int hooknum,
#endif
		struct sk_buff *skb, const struct net_device *in,
		const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph, _iph;
	struct udphdr *udph, _udph;
	struct udp_splice_entry *entry;
	struct udp_splice_ep *ep;
	struct udp_splice_tuple tuple;
	int idx;

	if (!in || !net_eq(dev_net(in), &init_net))
		goto accept;

	if (skb_shared(skb))
		goto accept;

	if (udp_splice_hook_ops.list.next != &nf_hooks[NFPROTO_IPV4][NF_INET_LOCAL_IN]) {
		schedule_work(&udp_splice_register_hook_work);
		goto accept;
	}

	iph = skb_header_pointer(skb, 0, sizeof(*iph), &_iph);
	if (!iph || ip_is_fragment(iph) || iph->protocol != IPPROTO_UDP)
		goto accept;
	/* It has some IP options, so let it pass. */
	if (iph->ihl * 4 != sizeof(*iph))
		goto accept;

	udph = skb_header_pointer(skb, sizeof(*iph), sizeof(*udph), &_udph);
	if (!udph)
		goto accept;
	if (ntohs(udph->len) + sizeof(*iph) != skb->len)
		goto accept;
	if (udph->check && !skb_csum_unnecessary(skb)) {
		skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
				ntohs(udph->len), IPPROTO_UDP, 0);
		if (__skb_checksum_complete(skb))
			goto accept;
	}

	tuple.laddr = iph->daddr;
	tuple.raddr = iph->saddr;
	tuple.lport = udph->dest;
	tuple.rport = udph->source;
	udp_splice_hash(&tuple);
	entry = udp_splice_find_entry(&tuple, &idx);
	if (!entry)
		goto accept;
	ep = &entry->ep[!idx];
	if (!skb_make_writable(skb, sizeof(*iph) + sizeof(*udph)))
		goto accept2;
	iph = (struct iphdr *)skb->data;
	udph = (struct udphdr *)(skb->data + sizeof(*iph));

	/* Decrease the TTL as a router does to avoid dead looping. */
	if (iph->ttl <= 1)
		goto drop2;
	ip_decrease_ttl(iph);

	if (udph->check) {
		inet_proto_csum_replace4(&udph->check, skb, iph->saddr,
				ep->tuple.laddr, 1);
		inet_proto_csum_replace4(&udph->check, skb, iph->daddr,
				ep->tuple.raddr, 1);
		inet_proto_csum_replace2(&udph->check, skb, udph->source,
				ep->tuple.lport, 0);
		inet_proto_csum_replace2(&udph->check, skb, udph->dest,
				ep->tuple.rport, 0);
	}
	udph->source = ep->tuple.lport;
	udph->dest = ep->tuple.rport;
	csum_replace4(&iph->check, iph->saddr, ep->tuple.laddr);
	iph->saddr = ep->tuple.laddr;
	csum_replace4(&iph->check, iph->daddr, ep->tuple.raddr);
	iph->daddr = ep->tuple.raddr;
	skb_forward_csum(skb);

	ep = &entry->ep[idx];
	spin_lock_bh(&ep->lock);
	ep->rx_packets++;
	ep->rx_bytes += skb->len - (sizeof(*iph) + sizeof(*udph));
	spin_unlock_bh(&ep->lock);

	entry->last_used = jiffies;

	udp_splice_put_entry(entry);

	/**
	 * The following lines are copied from skb_release_head_state() with
	 * minor modification, so please check that function to keep the code 
	 * synchronized and correct.
	 */
#ifdef CONFIG_XFRM
	secpath_put(skb->sp);
	skb->sp = NULL;
#endif
	if (skb->destructor) {
		skb->destructor(skb);
		skb->destructor = NULL;
	}
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	nf_conntrack_put(skb->nfct);
	skb->nfct = NULL;
#endif
#ifdef CONFIG_BRIDGE_NETFILTER
	nf_bridge_put(skb->nf_bridge);
	skb->nf_bridge = NULL;
#endif
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = 0;
#endif
#endif

	if (ip_route_me_harder(skb, RTN_UNSPEC))
		goto drop;
	ip_local_out(skb);

	return NF_STOLEN;
accept2:
	udp_splice_put_entry(entry);
accept:
	return NF_ACCEPT;
drop2:
	udp_splice_put_entry(entry);
drop:
	return NF_DROP;
}

static struct nf_hook_ops udp_splice_hook_ops __read_mostly = {
	.hook		= udp_splice_hook,
	.owner		= THIS_MODULE,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_LOCAL_IN,
	.priority	= NF_IP_PRI_LAST,
};

#ifdef CONFIG_PROC_FS
struct udp_splice_seq_iter {
	unsigned int	bucket;
	struct rb_node	*node;
};

static void *__udp_splice_seq_start(struct seq_file *seq, loff_t off)
{
	unsigned int bucket;
	struct rb_node *node;

	for (bucket = 0; bucket < udp_splice_hash_table_size; bucket++) {
		for (node = rb_first(&udp_splice_hash_table[bucket]);
				node; node = rb_next(node)) {
			if (--off == 0) {
				struct udp_splice_seq_iter *iter;

				iter = kmalloc(sizeof(*iter), GFP_ATOMIC);
				if (!iter)
					goto out;
				iter->bucket = bucket;
				iter->node = node;
				return iter;
			}
		}
	}
out:
	return NULL;
}

static void *udp_splice_seq_start(struct seq_file *seq, loff_t *pos)
{
	spin_lock_bh(&udp_splice_hash_table_lock);
	if (!*pos)
		return SEQ_START_TOKEN;

	return __udp_splice_seq_start(seq, *pos);
}

static void *udp_splice_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct udp_splice_seq_iter *iter;

	++*pos;
	if (v == SEQ_START_TOKEN)
		return __udp_splice_seq_start(seq, *pos);
	iter = (struct udp_splice_seq_iter *)v;
	iter->node = rb_next(iter->node);
	if (iter->node)
		return iter;
	for (iter->bucket++; iter->bucket < udp_splice_hash_table_size;
			iter->bucket++) {
		iter->node = rb_first(&udp_splice_hash_table[iter->bucket]);
		if (iter->node)
			return iter;
	}
	kfree(iter);

	return NULL;
}

static void udp_splice_seq_stop(struct seq_file *seq, void *v)
{
	spin_unlock_bh(&udp_splice_hash_table_lock);
	if (v && v != SEQ_START_TOKEN)
		kfree(v);
}

static int udp_splice_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "portid\ttimeout\t"
				"laddr:lport\traddr:rport\tpackets\tbytes\t"
				"laddr:lport\traddr:rport\tpackets\tbytes\n");
	} else {
		struct udp_splice_seq_iter *iter = v;
		struct udp_splice_ep *ep = rb_entry(iter->node,
				struct udp_splice_ep, node);
		struct udp_splice_entry *entry;
		unsigned long timeout, curr;
		unsigned long long rx_packets, rx_bytes, rx_packets2, rx_bytes2;

		if (ep->idx != 0)
			goto out;
		entry = udp_splice_ep2entry(ep);

		timeout = entry->last_used + entry->timeout;
		curr = jiffies;
		if (time_after(timeout, curr))
			timeout = timeout - curr;
		else
			timeout = 0;
		timeout /= HZ;

		spin_lock_bh(&entry->ep[0].lock);
		rx_packets = entry->ep[0].rx_packets;
		rx_bytes = entry->ep[0].rx_bytes;
		spin_unlock_bh(&entry->ep[0].lock);

		spin_lock_bh(&entry->ep[1].lock);
		rx_packets2 = entry->ep[1].rx_packets;
		rx_bytes2 = entry->ep[1].rx_bytes;
		spin_unlock_bh(&entry->ep[1].lock);

		seq_printf(seq,
			   "%u\t%lu\t%pI4:%u\t%pI4:%u\t%llu\t%llu\t"
			   "%pI4:%u\t%pI4:%u\t%llu\t%llu\n",
			   entry->portid, timeout,
			   &entry->ep[0].tuple.laddr,
			   ntohs(entry->ep[0].tuple.lport),
			   &entry->ep[0].tuple.raddr,
			   ntohs(entry->ep[0].tuple.rport),
			   rx_packets, rx_bytes,
			   &entry->ep[1].tuple.laddr,
			   ntohs(entry->ep[1].tuple.lport),
			   &entry->ep[1].tuple.raddr,
			   ntohs(entry->ep[1].tuple.rport),
			   rx_packets2, rx_bytes2);
	}
out:
	return 0;
}

static const struct seq_operations udp_splice_seq_ops = {
	.start	= udp_splice_seq_start,
	.next	= udp_splice_seq_next,
	.stop	= udp_splice_seq_stop,
	.show	= udp_splice_seq_show,
};

static int udp_splice_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &udp_splice_seq_ops,
			sizeof(struct seq_net_private));
}

static const struct file_operations udp_splice_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= udp_splice_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_net,
};

static int udp_splice_init_net(struct net *net)
{
	if (net_eq(net, &init_net)) {
		if (!proc_create(UDP_SPLICE_GENL_NAME, S_IRUGO, net->proc_net,
					&udp_splice_seq_fops))
			return -ENOMEM;
	}

	return 0;
}

static void udp_splice_exit_net(struct net *net)
{
	if (net_eq(net, &init_net))
		remove_proc_entry(UDP_SPLICE_GENL_NAME, net->proc_net);
}
#else /* !CONFIG_PROC_FS */
static int udp_splice_init_net(struct net *net)
{
	return 0;
}

static void udp_splice_exit_net(struct net *net)
{
}
#endif /* CONFIG_PROC_FS */

static struct pernet_operations udp_splice_net_ops = {
	.init	= udp_splice_init_net,
	.exit	= udp_splice_exit_net,
};

static void udp_splice_flush_entries(int portid)
{
	struct rb_node *node, *next;
	struct udp_splice_ep *ep;
	struct udp_splice_entry *entry;
	unsigned int i;
	unsigned int table_size;

	spin_lock_bh(&udp_splice_hash_table_lock);
	table_size = udp_splice_hash_table_size;
	for (i = 0; i < table_size; i++) {
begin:
		for (node = rb_first(&udp_splice_hash_table[i]); node;
				node = next) {
			next = rb_next(node);
			ep = rb_entry(node, struct udp_splice_ep, node);
			entry = udp_splice_ep2entry(ep);
			if (portid && portid != entry->portid)
				continue;
			if (del_timer(&entry->timer)) {
				if (next == &entry->ep[!ep->idx].node)
					next = rb_next(next);
				__udp_splice_unlink_entry(entry);
				udp_splice_put_entry(entry);
				continue;
			}
			atomic_inc(&entry->ref);
			spin_unlock_bh(&udp_splice_hash_table_lock);
			if (del_timer_sync(&entry->timer)) {
				udp_splice_unlink_entry(entry);
				udp_splice_put_entry(entry);
			}
			udp_splice_put_entry(entry);
			spin_lock_bh(&udp_splice_hash_table_lock);
			if (table_size != udp_splice_hash_table_size) {
				table_size = udp_splice_hash_table_size;
				i = 0;
				goto begin;
			} else {
				next = rb_first(&udp_splice_hash_table[i]);
			}
		}
	}
	spin_unlock_bh(&udp_splice_hash_table_lock);
}

struct udp_splice_urelease_work {
	struct work_struct	w;
	int			portid;
};

static struct workqueue_struct *udp_splice_urelease_wq;

static void udp_splice_urelease(struct work_struct *work)
{
	struct udp_splice_urelease_work *w;

	w = container_of(work, struct udp_splice_urelease_work, w);
	udp_splice_flush_entries(w->portid);
	kfree(w);
}

static int udp_splice_genl_rcv_nl_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	struct netlink_notify *n = ptr;
	struct udp_splice_urelease_work *w;

	if (event != NETLINK_URELEASE || !net_eq(n->net, &init_net) ||
	    n->protocol != NETLINK_GENERIC)
		goto out;

	w = kmalloc(sizeof(*w), GFP_ATOMIC);
	if (w) {
		INIT_WORK(&w->w, udp_splice_urelease);
		w->portid = n->portid;
		queue_work(udp_splice_urelease_wq, &w->w);
	} else {
		WARN_ONCE(true, "udp_splice: OOM when trying to flush entries "
				"by portid\n");
	}
out:
	return NOTIFY_DONE;
}

static struct notifier_block nl_notifier = {
	.notifier_call	= udp_splice_genl_rcv_nl_event,
};

static int __init init(void)
{
	int retval;

	if (udp_splice_hash_table_size == 0) {
		udp_splice_hash_table_size =
				(((totalram_pages << PAGE_SHIFT) / 16384) /
				 sizeof(*udp_splice_hash_table));
		if (totalram_pages > (1024 * 1024 * 1024 / PAGE_SIZE))
			udp_splice_hash_table_size = 16384;
		if (udp_splice_hash_table_size < 32)
			udp_splice_hash_table_size = 32;
	}

	udp_splice_hash_table = udp_splice_alloc_hash_table(
			&udp_splice_hash_table_size);
	if (!udp_splice_hash_table) {
		retval = -ENOMEM;
		goto err;
	}

	retval = nf_register_hook(&udp_splice_hook_ops);
	if (retval)
		goto err2;

	retval = register_pernet_subsys(&udp_splice_net_ops);
	if (retval)
		goto err3;

	udp_splice_urelease_wq = alloc_workqueue("udp_splice_urelease", 0, 1);
	if (!udp_splice_urelease_wq) {
		retval = -ENOMEM;
		goto err4;
	}
	BUG_ON(netlink_register_notifier(&nl_notifier));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	retval = genl_register_family_with_ops(&udp_splice_family,
			udp_splice_ops);
#else
	retval = genl_register_family_with_ops(&udp_splice_family,
			udp_splice_ops, ARRAY_SIZE(udp_splice_ops));
#endif
	if (retval)
		goto err5;

	pr_info("version %d (%u buckets)\n", UDP_SPLICE_GENL_VERSION,
			udp_splice_hash_table_size);

	return 0;
err5:
	BUG_ON(netlink_unregister_notifier(&nl_notifier));
	destroy_workqueue(udp_splice_urelease_wq);
err4:
	unregister_pernet_subsys(&udp_splice_net_ops);
err3:
	mutex_lock(&udp_splice_register_lock);
	if (!list_empty(&udp_splice_hook_ops.list))
		nf_unregister_hook(&udp_splice_hook_ops);
	udp_splice_register = false;
	mutex_unlock(&udp_splice_register_lock);
	flush_work(&udp_splice_register_hook_work);
err2:
	udp_splice_free_hash_table(udp_splice_hash_table,
			udp_splice_hash_table_size);
err:
	return retval;
}
module_init(init);

static void __exit fini(void)
{
	BUG_ON(genl_unregister_family(&udp_splice_family));
	BUG_ON(netlink_unregister_notifier(&nl_notifier));
	destroy_workqueue(udp_splice_urelease_wq);
	unregister_pernet_subsys(&udp_splice_net_ops);
	mutex_lock(&udp_splice_register_lock);
	if (!list_empty(&udp_splice_hook_ops.list))
		nf_unregister_hook(&udp_splice_hook_ops);
	udp_splice_register = false;
	mutex_unlock(&udp_splice_register_lock);
	flush_work(&udp_splice_register_hook_work);
	udp_splice_flush_entries(0);
	udp_splice_free_hash_table(udp_splice_hash_table,
			udp_splice_hash_table_size);
}
module_exit(fini);
