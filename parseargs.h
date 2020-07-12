#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

struct args_t {
	char *table;
	char *chain;
	char *src;
	char *dst;
	char *action;
	char flag;
	int rulenum;
};

void usage(char **argv);
int parseargs(struct args_t *args, int argc, char **argv);
void print_args(struct args_t *args);
