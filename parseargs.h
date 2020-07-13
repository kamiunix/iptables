/**  
 * @brief example use of libiptc to programaticaly edit firewall rules
 *
 * @author Samuel Champagne 
 *
 * Contact: sam.c.tur@gmail.com
 */

#ifndef PARSEARGS_FILE
#define PARSEARGS_FILE

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "iptables.h"

/* arguments object contain all arguments passed to application after parsing */
struct args_t {
	char *table;
	char *chain;
	char *src;
	char *dst;
	char *action;
	char flag;
	int rulenum;
	__u16 prot;
};

void usage(char **argv);
int parseargs(struct args_t *args, int argc, char **argv);
void print_args(struct args_t *args);

#endif
