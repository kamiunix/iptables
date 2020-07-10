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
	out:   
		if (h)     iptc_free(h);    
		return ret;
}


int main(int argc, char **argv) {   
	unsigned int a, b;   
       	inet_pton(AF_INET, "1.2.3.4", &a);  
       	inet_pton(AF_INET, "4.3.2.1", &b);   
       	insert_rule("filter", "INPUT", a, 0, b, 1, "DROP");   
	return 0; 
}
