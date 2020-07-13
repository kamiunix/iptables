/**  
 * @brief example use of libiptc to programaticaly edit firewall rules
 *
 * @author Samuel Champagne 
 *
 * Contact: sam.c.tur@gmail.com
 */

#include "parseargs.h"

/*
 * function to print usage of this application in the command line
 * @param argv: arguments array passed to this application
 */
void usage(char **argv) {
	printf("%s [OPTION] <VALUE>\n", argv[0]);
	printf("  %s\n", "-t [ARG]\t\tTable to add entries to\n\t\t\t\tdefault:filter");
	printf("  %s\n", "-c [ARG]\t\tChain to add entries to\n\t\t\t\tdefault:INPUT");
	printf("  %s\n", "-s [ARG]\t\tSource IP of rule\n\t\t\t\tdefault:1.2.3.4");
	printf("  %s\n", "-d [ARG]\t\tDestination IP of rule\n\t\t\t\tdefault:4.3.2.1");
	printf("  %s\n", "-n [ARG]\t\tRulenum to remove or change [int]\n\t\t\t\tdefault:0");
	printf("  %s\n", "-a [ARG]\t\taction to perform with given rule\n\t\t\t\tdefault:ACCEPT");
	printf("  %s\n", "-p [ARG]\t\tport to apply filtering to\n\t\t\t\tdefault:0 = ANY");
	printf("  %s\n", "-e \t\tempty a given table");
	printf("  %s\n", "-i \t\tInsert a given rule into table");
	printf("  %s\n", "-m \t\tchange a rule in table at given index with given rule");
	printf("  %s\n", "-r \t\tremove a rule at given index in table");
	printf("  %s\n", "-l \t\tlist all rules in table");
	printf("  %s\n", "-L \t\tlist all rules in table with given chain");
	printf("  %s\n", "-T \t\ttest basic functionality of the application");
}

/*
 * main function that parses arguments and returns a passed args_t object populated
 * @param args_t: argument object to be populated
 * @param argc: count of number of arguments passed to this application
 * @param argv: arguments array passed to this application
 *
 * @return int: successfull parsing returns a 0
 *
 * I've opted to populate default values for better demonstration of application functionality 
 * but this could be refactored easily if desired.
 */
int parseargs(struct args_t *args, int argc, char **argv) {

	//populate default values
	args->table = "filter";
	args->chain = "INPUT";
	args->src = "1.2.3.4";
	args->dst = "4.3.2.1";
	args->action = "ACCEPT";
	args->flag = 'l';
	args->rulenum = 0;

	int c;
	
	//loop to parse all arguments provided
	while ((c = getopt(argc, argv, "t:c:s:d:n:a:p:eimrlLT")) != -1) {
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
			case 'p':
				args->prot = (__u16) atoi(optarg);
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
			case 'L':
				args->flag = 'L';
				break;
			case 'T':
				args->flag = 'T';
				break;
			default:
				usage(argv);
				return 0;
		}
	}
}

/*
 * prints the detauls of a given args_t object in human readable format
 * @param args: args_t object to print
 */
void print_args(struct args_t *args) {
	printf("table: %s\n", args->table);
	printf("chain: %s\n", args->chain);
	printf("src: %s\n", args->src);
	printf("dst: %s\n", args->dst);
	printf("prot: %u\n", args->prot);
	printf("action: %s\n", args->action);
	printf("flag: %c\n", args->flag);
	printf("rulenum: %u\n", args->rulenum);
}
