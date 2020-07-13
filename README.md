### Installing

```
gcc -o iptable main.c iptables.c parseargs.c `pkg-config --cflags --libs libiptc` -ldl
```

### Docker

Docker container available from samuelct/iptables

```
docker pull samuelct/iptables
```

make sure to run docker with special capabilities via --cap-add=NET_ADMIN with

```
docker run --cap-add=NET_ADMIN -it samuelct/iptables 
```

iptables files are located in /root/iptables/

```
cd /root/iptables/
```

to get help information just run the following

```
./iptable
```

to test basic functionality just run the following

```
./iptable -T
```

### Documentation

this applicaiton can list (list_rules), add (insert_rule), modify (replace_rule) and delete (delete_rule) iptables rules, in multiple user defined chains. The four main functions that demonstrate functionality (in parentheses above) make use of multipple libiptc functions in /usr/include/libiptc/libiptc.h (iptc_first/next_chain and iptc_first/next_rule, iptc_append_entry, iptc_replace_entry, iptc_delete_num_entry (respectively)). 


### Code Segments

iptables.c

contains functionality to list rules, insert rule, replace rule and delete rule. Iused the libiptc library to create rule entries and add them to the firewall. Further functions can be created using function definitions in libiptc.h should they be required. The most challenging part of this section was figuring out how to print data to display it readably and creating entries which could be passed around to be modify chains in a table.
parseargs.c

contains functionality to parse commandline arguments and return an args_t strucuture with all arguments contained and inialized.

main.c

entry point of the program which makes calls to parseargs.c and iptables.c. 



### PostMortem

The application currently only processes one action at a time and thus must be called multipple times if you want to add multipple rules or do multipple things. Adding an action queue of args_t structs would be a good way of processing multipple actions with one call. As time was running out and the problem definition did not specify if this was a requirement I opted to avoid doing this in favor of refactoring and documenting.

I have a much better understanding of libiptc now and I believe it wouldn't be too difficult to expand functionality of this application to include more test cases and options. I opted to make the delete_rule and replace_rule options require a rulenum integer of which rule you wish to replace but it wouldn't be too dificult to change this to require a rule entry structure we want to replace.

The command line interface is pretty rough, and needs to be enhanced and extended to be more clean and versatile but the current structure should allow for easy growth and developement should more features be required.

Overall this task was very interesting and fun to work through. I wish I'd had more time to make the application more versatile but I believe it meets the requirements of the problem as is.
