#include "parseargs.h"

void usage(char **argv) {
	printf("%s [OPTION] <VALUE>\n", argv[0]);
	printf("  %s\n", "-t [ARG]\t\tTable to add entries to\n\t\t\t\tdefault:filter");
	printf("  %s\n", "-c [ARG]\t\tChain to add entries to\n\t\t\t\tdefault:INPUT");
	printf("  %s\n", "-s [ARG]\t\tSource IP of rule\n\t\t\t\tdefault:1.2.3.4");
	printf("  %s\n", "-d [ARG]\t\tDestination IP of rule\n\t\t\t\tdefault:4.3.2.1");
	printf("  %s\n", "-n [ARG]\t\tRulenum to remove or change [int]\n\t\t\t\tdefault:0");
	printf("  %s\n", "-a [ARG]\t\taction to perform with given rule\n\t\t\t\tdefault:ACCEPT");
	printf("  %s\n", "-e \t\tempty a given table");
	printf("  %s\n", "-i \t\tInsert a given rule into table");
	printf("  %s\n", "-m \t\tchange a rule in table at given index with given rule");
	printf("  %s\n", "-r \t\tremove a rule at given index in table");
	printf("  %s\n", "-l \t\tlist all rules in table");
}

int parseargs(struct args_t *args, int argc, char **argv) {
	args->table = "filter";
	args->chain = "INPUT";
	args->src = "1.2.3.4";
	args->dst = "4.3.2.1";
	args->action = "ACCEPT";
	args->flag = 'l';
	args->rulenum = 0;

	int c;
	while ((c = getopt(argc, argv, "t:c:s:d:n:a:eimrl")) != -1) {
		switch (c) {
			case 't':
				args->table = optarg;
				break;
			case 'c':
				args->chain = optarg;
				break;
			case 's':
				args->src = optarg;
				break;
			case 'd':
				args->dst = optarg;
				break;
			case 'n':
				args->rulenum = atoi(optarg);
				break;
			case 'a':
				args->action = optarg;
				break;
			case 'e':
				args->flag = 'e';
				break;
			case 'i':
				args->flag = 'i';
				break;
			case 'm':
				args->flag = 'm';
				break;
			case 'r':
				args->flag = 'r';
				break;
			case 'l':
				args->flag = 'l';
				break;
			default:
				usage(argv);
				return 0;
		}
	}
}

void print_args(struct args_t *args) {
	printf("table: %s\n", args->table);
	printf("chain: %s\n", args->chain);
	printf("src: %s\n", args->src);
	printf("dst: %s\n", args->dst);
	printf("action: %s\n", args->action);
	printf("flag: %c\n", args->flag);
	printf("rulenum: %u\n", args->rulenum);
}

/*
static int main(int argc, char **argv) {
	struct args_t args;
	memset(&args, 0, sizeof(args));

	if (!parseargs(&args, argc, argv)) {
		printf("%s\n", "Error parsing input");
		return 1;
	}
	print_args(&args);
}
*/
