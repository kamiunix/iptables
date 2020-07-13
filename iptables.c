/**  
 * @brief example use of libiptc to programaticaly edit firewall rules
 *
 * @author Samuel Champagne 
 *
 * Contact: sam.c.tur@gmail.com
 */

#include "iptables.h"

/**
 * Intializes the given entries parameters 
 * @param entry_t: entry to populate
 * @param src: source ip
 * @param inverted_src: inverted source ip
 * @param dest: destination ip
 * @param inverted_dest: inverted destination ip
 * @param target: the targeted action to be taken
 * @param proto: protocol references in rule
 */
void initialize_entry(struct entry_t *entry, unsigned int src, int inverted_src, unsigned int dest, int inverted_dest, const char *target, __u16 proto) {

	/* target */
	entry->target.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
	strncpy (entry->target.target.u.user.name, target, sizeof (entry->target.target.u.user.name));

	/* entry */
	entry->entry.target_offset = sizeof (struct ipt_entry);
	entry->entry.next_offset = entry->entry.target_offset + entry->target.target.u.user.target_size;

	if (src) {
		entry->entry.ip.src.s_addr = src;
		entry->entry.ip.smsk.s_addr = 0xFFFFFFFF;
		if (inverted_src) {
			entry->entry.ip.invflags |= IPT_INV_SRCIP;
		}
	}

	if (dest) {
		entry->entry.ip.dst.s_addr  = dest;
		entry->entry.ip.dmsk.s_addr = 0xFFFFFFFF;
		if (inverted_dest)
			entry->entry.ip.invflags |= IPT_INV_DSTIP;
	}

	if (proto > 0) {
		entry->entry.ip.proto = proto;
	}
}

/*
 * cleansup memmory for the handler before exiting the application
 * @param xtc_handle: handle to cleanup
 * @param ret: return code to return
 * @return: exit code of application
 */
int cleanup(int ret, struct xtc_handle *h) {
	if (h)
		iptc_free (h);
	return ret;
}

/*
 * function to print interface info
 * @param iface: iface in question
 * @param mask: mask to be applied to iface
 * @param inverted: inversion value to be aplied
 */
void print_iface(const unsigned char *iface, const unsigned char *mask, int invert) {
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

/*
 * function to print protocol details
 * @param proto: protocol in question
 * @param inverted: inversion value to be applied
 */
void print_proto(u_int16_t proto, int invert) {
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

/* print a given ip including mask if neccessary 
 * @param ip: ip to print
 * @param mask: mask to be applied to ip
 * @param invert: inversion to be applied
 */
void print_ip(u_int32_t ip, u_int32_t mask, int invert) {

	printf("%s%u.%u.%u.%u",
			invert ? "! " : "",
			IP_PARTS(ip));

	if (mask != 0xffffffff)
		printf("/%u.%u.%u.%u ", IP_PARTS(mask));
	else
		printf(" ");
}

/* 
 * print the rule parameters of a given xtc_handle chain and entity 
 * @param ipt_entry: entry to print
 * @param xtc_handle: handle of iptc
 * @param chain: chain of entry
 * @param counters: counter of entry
 */
void print_rule(const struct ipt_entry *e, struct xtc_handle *h, const char *chain, int counters) {
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

/*
 * print all rules of a given table
 * @param table: table of which we want to print the rules
 *
 * @return int: successful if returns 0
 */
int list_rules(const char *table) {
	struct xtc_handle *h;   
	const struct ipt_entry *e;
	const int counters = 1;
	const char *chain = NULL;
	
	h = iptc_init(table);   
	if (!h) {
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		return cleanup(ret, h);
	}

	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h)) {
		for (e = iptc_first_rule(chain, h); e; e = iptc_next_rule(e, h))  { 
			print_rule(e, h, chain, counters);  
		}
	}
	return cleanup(0, h);
}

/*
 * Insert a rule to given chain in a table with given parameters
 * @param table: table of chain
 * @param chain: chain to add rule to
 * @param src: source ip
 * @param inverted_src: inverted source ip
 * @param dest: destination ip
 * @param inverted_dest: inverted destination ip
 * @param target: the targeted action to be taken
 *
 * @return int: successful if returns 0
 */
int insert_rule(const char *table, const char *chain, unsigned int src, int inverted_src, unsigned int dest, int inverted_dest, const char *target) {
	//initalizing required structures and variables
	struct xtc_handle *h;   
	struct entry_t entry;

	//get iptables handle
	h = iptc_init(table);   
	if (!h) {       
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		return cleanup(errno, h);
	}

	//create entry with given parameters
	memset(&entry, 0, sizeof(entry));
	initialize_entry(&entry, src, inverted_src, dest, inverted_dest, target, 0);

	//insert rules in iptables
	if (!iptc_append_entry (chain, (struct ipt_entry *) &entry, h)) {
		fprintf (stderr, "Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
		return cleanup(errno, h);
	}

	//commit changes to iptables
	if (!iptc_commit (h)) {
		fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
		return cleanup(errno, h);
	}

	return cleanup(0, h);
}


/*
 * replace a rule to given chain in a table with given parameters at given location (int)
 * @param table: table of chain
 * @param chain: chain to add rule to
 * @param src: source ip
 * @param inverted_src: inverted source ip
 * @param dest: destination ip
 * @param inverted_dest: inverted destination ip
 * @param target: the targeted action to be taken
 * @param rulenum: index of rule to be changed
 *
 * @return int: successful if returns 0
 */
int replace_rule(const char *table, const char *chain, unsigned int src, int inverted_src, unsigned int dest, int inverted_dest, const char *target, unsigned int rulenum) {
	struct entry_t entry;
	struct xtc_handle *h;   

	h = iptc_init(table);   
	if (!h) {       
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		return cleanup(errno, h);
	}

	//create entry with given parameters
	memset(&entry, 0, sizeof(entry));
	initialize_entry(&entry, src, inverted_src, dest, inverted_dest, target, 0);

	if (!iptc_replace_entry (chain, (struct ipt_entry *) &entry, rulenum, h)) {
		fprintf (stderr, "Could not insert a rule in iptables (table %s) at (rulenum : %u) %s\n", table, rulenum, iptc_strerror (errno));
		return cleanup(errno, h);
	}

	if (!iptc_commit (h)) {
		fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
		return cleanup(errno, h);
	}

	return cleanup(0, h);
}

/*
 * delete a rule in given chain in a table at given location (int)
 * @param table: table of chain
 * @param chain: chain to add rule to
 * @param rulenum: index of rule to be changed
 *
 * @return int: successful if returns 0
 */
int delete_rule(const char *table, const char *chain, unsigned int rulenum) {
	struct xtc_handle *h;   
	h = iptc_init(table);   

	if (!h) {       
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		return cleanup(errno, h);
	}

	if (!iptc_delete_num_entry(chain, rulenum, h)) {
		fprintf (stderr, "Could not delete entry in iptables (table %s) at (rulenum : %u) in (chain: %s) %s\n", table, rulenum, chain, iptc_strerror (errno));
		return cleanup(errno, h);
	}

	if (!iptc_commit (h)) {
		fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
		return cleanup(errno, h);
	}

	return cleanup(0, h);
}

/*
 * clear all rules from a given table and chain
 * @param table: table of chain
 * @param chain: chain to add rule to
 *
 * @return int: successful if returns 0
 */
int clear_rules(const char *table, const char *chain) {
	struct xtc_handle *h;   

	h = iptc_init(table);   
	if (!h) {       
		fprintf(stderr, "Could not init IPTC library: %s\n", iptc_strerror(errno));       
		return cleanup(errno, h);
	}

	if (!iptc_flush_entries(chain, h)) {
		fprintf (stderr, "Could not flush entries in iptables (table %s) in (chain: %s) %s\n", table, chain, iptc_strerror (errno));
		return cleanup(errno, h);
	}

	if (!iptc_commit (h)) {
		fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
		return cleanup(errno, h);
	}

	return cleanup(0, h);
}
