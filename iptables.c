#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <libiptc/libiptc.h>

#define IP_PARTS_NATIVE(n)      \
	(unsigned int)((n)>>24)&0xFF,   \
	(unsigned int)((n)>>16)&0xFF,   \
	(unsigned int)((n)>>8)&0xFF,    \
	(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

static void print_iface(const unsigned char *iface, const unsigned char *mask, int invert) {
	unsigned int i;

	if (mask[0] == 0)
		return;

	printf(" %s", invert ? "! " : "");

	for (i = 0; i < IFNAMSIZ; i++) {
		if (mask[i] != 0) {
			if (iface[i] != '\0')
				printf("%c", iface[i]);
		} else {
			/* we can access iface[i-1] here, because
			 * a few lines above we make sure that mask[0] != 0 */
			if (iface[i-1] != '\0')
				printf("+");
			break;
		}
	}

	printf(" ");
}

/* These are hardcoded backups in iptables.c, so they are safe */
struct pprot {
	char *name;
	u_int8_t num;
};

static const struct pprot chain_protos[] = {
	{ "tcp", IPPROTO_TCP },
	{ "udp", IPPROTO_UDP },
	{ "icmp", IPPROTO_ICMP },
	{ "esp", IPPROTO_ESP },
	{ "ah", IPPROTO_AH },
};

static void print_proto(u_int16_t proto, int invert)
{
	if (proto) {
		unsigned int i;
		const char *invertstr = invert ? "! " : "";

		for (i = 0; i < sizeof(chain_protos)/sizeof(struct pprot); i++)
			if (chain_protos[i].num == proto) {
				printf("-p %s%s ",
						invertstr, chain_protos[i].name);
				return;
			}

		printf(" %s%u ", invertstr, proto);
	}
}

/* print a given ip including mask if neccessary */
static void print_ip(u_int32_t ip, u_int32_t mask, int invert)
{

	printf("%s%u.%u.%u.%u",
			invert ? "! " : "",
			IP_PARTS(ip));

	if (mask != 0xffffffff)
		printf("/%u.%u.%u.%u ", IP_PARTS(mask));
	else
		printf(" ");
}

/* We want this to be readable, so only print out neccessary fields.
 * Because that's the kind of world I want to live in.  */
static void print_rule(const struct ipt_entry *e,
		struct xtc_handle *h, const char *chain, int counters)
{
	struct ipt_entry_target *t;
	const char *target_name;

	/* print chain name */
	printf("%s ", chain);

	/* Print IP part. */
	print_ip(e->ip.src.s_addr,e->ip.smsk.s_addr,
			e->ip.invflags & IPT_INV_SRCIP);

	print_ip(e->ip.dst.s_addr, e->ip.dmsk.s_addr,
			e->ip.invflags & IPT_INV_DSTIP);

	print_iface(e->ip.iniface, e->ip.iniface_mask,
			e->ip.invflags & IPT_INV_VIA_IN);

	print_iface(e->ip.outiface, e->ip.outiface_mask,
			e->ip.invflags & IPT_INV_VIA_OUT);

	print_proto(e->ip.proto, e->ip.invflags & IPT_INV_PROTO);

	if (e->ip.flags & IPT_F_FRAG)
		printf("%s",
				e->ip.invflags & IPT_INV_FRAG ? "! " : "");


	/* Print target name */
	target_name = iptc_get_target(e, h);
	if (target_name && (*target_name != '\0'))
		printf("%s ", target_name);

	/* Print targinfo part */
	t = ipt_get_target((struct ipt_entry *)e);
	if (t->u.user.name[0]) {

		/* If the target size is greater than ipt_entry_target
		 * there is something to be saved, we just don't know
		 * how to print it */
		if (t->u.target_size !=
				sizeof(struct ipt_entry_target)) {
			fprintf(stderr, "Target `%s' is missing "
					"save function\n",
					t->u.user.name);
			exit(1);
		}
	}
	printf("\n");
}

static void list_rules(const char *table) {
	struct xtc_handle *h;   
	const struct ipt_entry *e;
	const int counters = 1;
	const char *chain = NULL;
	h = iptc_init(table);   

	if (!h) {
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		exit(errno);
	}

	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h)) {
		for (e = iptc_first_rule(chain, h); e; e = iptc_next_rule(e, h))  { 
			print_rule(e, h, chain, counters);  
		}
	}
}

static int insert_rule(const char *table, 
		const char *chain, 
		unsigned int src, 
		int inverted_src, 
		unsigned int dest, 
		int inverted_dest, 
		const char *target)
{
	struct {       
		struct ipt_entry entry;
		struct xt_standard_target target;
	} entry;  
	struct xtc_handle *h;   
	int ret = 1;    

	h = iptc_init(table);   
	if (!h) {       
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		goto out;     
	}

	memset (&entry, 0, sizeof (entry));

	/* target */
	entry.target.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
	strncpy (entry.target.target.u.user.name, target, sizeof (entry.target.target.u.user.name));

	/* entry */
	entry.entry.target_offset = sizeof (struct ipt_entry);
	entry.entry.next_offset = entry.entry.target_offset + entry.target.target.u.user.target_size;

	if (src) {
		entry.entry.ip.src.s_addr = src;
		entry.entry.ip.smsk.s_addr = 0xFFFFFFFF;
		if (inverted_src) {
			entry.entry.ip.invflags |= IPT_INV_SRCIP;
		}
	}
	if (dest) {
		entry.entry.ip.dst.s_addr  = dest;
		entry.entry.ip.dmsk.s_addr = 0xFFFFFFFF;
		if (inverted_dest)
			entry.entry.ip.invflags |= IPT_INV_DSTIP;
	}

	if (!iptc_append_entry (chain, (struct ipt_entry *) &entry, h)) {
		fprintf (stderr, "Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
		goto out;
	}

	if (!iptc_commit (h)) {
		fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
		goto out;
	}

	ret = 0;
out:
	if (h)
		iptc_free (h);

	return ret;
}

static int replace_rule(const char *table, 
		const char *chain, 
		unsigned int src, 
		int inverted_src, 
		unsigned int dest, 
		int inverted_dest, 
		const char *target,
		unsigned int rulenum)
{
	struct {       
		struct ipt_entry entry;
		struct xt_standard_target target;
	} entry;  
	struct xtc_handle *h;   
	int ret = 1;    

	h = iptc_init(table);   
	if (!h) {       
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		goto out;     
	}

	memset (&entry, 0, sizeof (entry));

	/* target */
	entry.target.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
	strncpy (entry.target.target.u.user.name, target, sizeof (entry.target.target.u.user.name));

	/* entry */
	entry.entry.target_offset = sizeof (struct ipt_entry);
	entry.entry.next_offset = entry.entry.target_offset + entry.target.target.u.user.target_size;

	if (src) {
		entry.entry.ip.src.s_addr = src;
		entry.entry.ip.smsk.s_addr = 0xFFFFFFFF;
		if (inverted_src) {
			entry.entry.ip.invflags |= IPT_INV_SRCIP;
		}
	}
	if (dest) {
		entry.entry.ip.dst.s_addr  = dest;
		entry.entry.ip.dmsk.s_addr = 0xFFFFFFFF;
		if (inverted_dest)
			entry.entry.ip.invflags |= IPT_INV_DSTIP;
	}

	if (!iptc_replace_entry (chain, (struct ipt_entry *) &entry, rulenum, h)) {
		fprintf (stderr, "Could not insert a rule in iptables (table %s) at (rulenum : %u) %s\n", table, rulenum, iptc_strerror (errno));
		goto out;
	}

	if (!iptc_commit (h)) {
		fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
		goto out;
	}

	ret = 0;
out:
	if (h)
		iptc_free (h);

	return ret;

	
}

static int delete_rule(const char *table, 
		const char *chain, 
		unsigned int rulenum)
{
	struct xtc_handle *h;   
	int ret = 1;    

	h = iptc_init(table);   
	if (!h) {       
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		goto out;     
	}
	if (!iptc_delete_num_entry(chain, rulenum, h)) {
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		goto out;     
	}
	if (!iptc_commit (h)) {
		fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
		goto out;
	}
	ret = 0;
out:
	if (h)
		iptc_free (h);

	return ret;
}

static int clear_rules(const char *table,
		const char *chain) 
{
	struct xtc_handle *h;   
	int ret = 1;    

	h = iptc_init(table);   
	if (!h) {       
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		goto out;     
	}
	if (!iptc_flush_entries(chain, h)) {
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		goto out;     
	}
	if (!iptc_commit (h)) {
		fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
		goto out;
	}
	ret = 0;
out:
	if (h)
		iptc_free (h);

	return ret;
}


int main(int argc, char **argv) {   
	unsigned int a, b, c;   
	inet_pton(AF_INET, "1.2.3.4", &a);  
	inet_pton(AF_INET, "4.3.2.1", &b);   
	inet_pton(AF_INET, "1.1.1.1", &c);   

	clear_rules("filter", "INPUT");
	list_rules("filter");

	printf("%s\n", "inserting rules");
	insert_rule("filter", "INPUT", a, 0, b, 1, "DROP");   
	insert_rule("filter", "INPUT", a, 0, c, 1, "DROP");   
	list_rules("filter");

	printf("%s %u\n", "replacing rule", 1);
	replace_rule("filter", "INPUT", a, 0, b, 1, "ACCEPT", 1);   
	list_rules("filter");

	printf("%s %u\n", "deleting rule", 0);
	delete_rule("filter", "INPUT", 0);
	list_rules("filter");

	return 0; 
}
