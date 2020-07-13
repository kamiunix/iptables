/**  
 * @brief example use of libiptc to programaticaly edit firewall rules
 *
 * @author Samuel Champagne 
 *
 * Contact: sam.c.tur@gmail.com
 */

#include "parseargs.h"
#include "iptables.h"

/*
 * Test function to test basic functionality of the 4 main requirements of this programming challenge
 *
 * @return int: successfull completion of the test returns 0
 */
int test() {   
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

/*
 * entry point of the iptable custom application
 *
 * @param argc: number of arguments passed from command line
 * @param argv: array containing all arguments passed from command line
 *
 * @return int: successfull completion of the application returns 0
 */
int main(int argc, char **argv) {
	struct args_t args;
	memset(&args, 0, sizeof(args));

	// parse all arguments and return 1 if it wasn't parsed properly
	if (!parseargs(&args, argc, argv)) {
		printf("%s\n", "Error parsing input");
		return 1;
	}

	// print all arguments received (and default values if not passed)
	printf("%s\n", "Received arguments:");
	print_args(&args);

	//change the ips to machine requirements
	unsigned int src, dst;   
	inet_pton(AF_INET, args.src, &src);  
	inet_pton(AF_INET, args.dst, &dst);   
	
	/* switch based on the required action to perform from the requirements:
	 * list (l), add (i), modify (m), and delete (r) iptables rules.
	 */
	switch (args.flag) {
		case 'i':
			printf("%s\n", "inserting rule into table");
			insert_rule(args.table, args.chain, src, 0, dst, 1, args.action);
			break;
		case 'c':
			printf("%s\n", "clearing table");
			clear_rules(args.table, args.chain);
			break;
		case 'l':
			printf("%s\n", "listing rules in table");
			list_rules(args.table);
			break;
		case 'm':
			printf("%s\n", "replacing rule in table at given location");
			replace_rule(args.table, args.chain, src, 0, dst, 1, args.action, args.rulenum);
			break;
		case 'r':
			printf("%s\n", "deleting rule in table at given location");
			delete_rule(args.table, args.chain, args.rulenum);
			break;
		case 't':
			printf("%s\n", "testing all functions");
			test();
			break;
		default:
			usage(argv);
			return 1;
	}

	return 0;
}
