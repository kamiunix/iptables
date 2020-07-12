#include <stdio.h>
#include <unistd.h>
#include <string.h>

struct args_t {
	char *table;
	char *chain;
	char *src;
	char *dst;
};

static void usage(char **argv) {
	printf("%s [OPTION] <VALUE>\n", argv[0]);
	printf("  %s\n", "-t [ARG]\t\tTable to add entries to\n\t\t\t\tdefault:filter");
	printf("  %s\n", "-c [ARG]\t\tChain to add entries to\n\t\t\t\tdefault:INPUT");
	printf("  %s\n", "-s [ARG]\t\tSource IP of rule\n\t\t\t\tdefault:1.2.3.4");
	printf("  %s\n", "-d [ARG]\t\tDestination IP of rule\n\t\t\t\tdefault:4.3.2.1");
}

static int parseargs(struct args_t *args, int argc, char **argv) {
	args->table = "filter";
	args->chain = "INPUT";
	args->src = "1.2.3.4";
	args->dst = "4.3.2.1";

	int c;
	while ((c = getopt(argc, argv, "t:c:s:d:")) != -1) {
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
			default:
				usage(argv);
				return 0;
		}
	}
}

static void print_args(struct args_t *args) {
	printf("table: %s\n", args->table);
	printf("chain: %s\n", args->chain);
	printf("src: %s\n", args->src);
	printf("dst: %s\n", args->dst);
}

int main(int argc, char **argv) {
	struct args_t args;
	memset(&args, 0, sizeof(args));

	if (!parseargs(&args, argc, argv)) {
		printf("%s\n", "Error parsing input");
		return 1;
	}
	print_args(&args);
}
