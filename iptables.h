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

struct entry_t {       
	struct ipt_entry entry;
	struct xt_standard_target target;
};  

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

void initialize_entry(struct entry_t *entry, unsigned int src, int inverted_src, unsigned int dest, int inverted_dest, const char *target, __u16 proto);
void print_iface(const unsigned char *iface, const unsigned char *mask, int invert);
void print_proto(u_int16_t proto, int invert);
void print_ip(u_int32_t ip, u_int32_t mask, int invert);
int cleanup(int ret, struct xtc_handle *h);

void print_rule(const struct ipt_entry *e, struct xtc_handle *h, const char *chain, int counters);
int list_rules(const char *table);
int insert_rule(const char *table, const char *chain, unsigned int src, int inverted_src, unsigned int dest, int inverted_dest, const char *target);
int replace_rule(const char *table, const char *chain, unsigned int src, int inverted_src, unsigned int dest, int inverted_dest, const char *target, unsigned int rulenum);
int delete_rule(const char *table, const char *chain, unsigned int rulenum);
int clear_rules(const char *table, const char *chain);