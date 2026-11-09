#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <signal.h>

// initializing the signal
volatile sig_atomic_t keep_running = 1;

// signal handler
void handle_signal(int sig){
	keep_running = 0;
}

int main(int argc, char **argv){

	signal(SIGINT,handle_signal);
	signal(SIGTERM,handle_signal);

	// taking the network interface as an argument from commandline
	if (argc<2){
		fprintf(stderr,"Exceeds the number of arguements",argv[0]);
		return 1;
	}
	char *interface = argv[1];
	int interface_number = if_nametoindex(interface);
	if (interface_number == 0){
		fprintf(stderr,"Error with the interface number");
		return 1;
	}
	printf("\nInterface number has been found\n");

	// opening the file to get the data for the ip and ports
	FILE *IPfile = fopen("/etc/IP_blacklist.txt","r");
	if (!IPfile){
		fprintf(stderr,"Error opening IP_blacklist.txt");
		return 1;
	}
	printf("\nAble to open IP_blacklist.txt\n");
	FILE *PORTfile = fopen("/etc/Port_whitelist.txt","r");
	if (!PORTfile){
		fprintf(stderr,"Error opening Port_whitelist.txt");
		fclose(IPfile);
		return 1;
	}
	printf("\nAble to open Port_whitelist.txt\n");

	// opening the object file and loading the maps
	const char *path = "/etc/ebpf_whitelists.bpf.o";
	struct bpf_object *object = bpf_object__open(path);
	if (!object){
		fprintf(stderr, "Error with the object");
		return 1;
	}
	printf("\nObject obtained with no issue\n");
	int kernel_loaded = bpf_object__load(object);
	if (kernel_loaded != 0){
		printf("Error loading the object to the kernel");
		return 1;
	}
	printf("\nKernel loaded with no issue\n");

	// finding the maps by name
	const char *ip_blacklist = "ip_blacklist";
	const char *port_whitelist = "port_whitelist";
	struct bpf_map *ipmap = bpf_object__find_map_by_name(object,ip_blacklist);
	struct bpf_map *portmap = bpf_object__find_map_by_name(object,port_whitelist);
	int ip_blacklist_fd = bpf_object__find_map_fd_by_name(object,ip_blacklist);
	int port_whitelist_fd = bpf_object__find_map_fd_by_name(object,port_whitelist);
	if (ip_blacklist_fd < 0 || port_whitelist_fd < 0){
		printf("Error finding ip and port hashmaps");
		fclose(IPfile);
		fclose(PORTfile);
		return 1;
	}
	printf("\nMaps found successfully\n");
	// using the fd to add to the data
	char ip[16];
	char port[6];
	int ips;
	int ports;
	__u32 ipaddr;
	__u16 portnumber;
	__u32 val = 1;
	while (fgets(ip,sizeof(ip),IPfile) != NULL){
		if (strlen(ip)==0) continue;
		ip[strcspn(ip,"\n")]='\0';
		inet_pton(AF_INET,ip,&ipaddr);
		ips = bpf_map_update_elem(ip_blacklist_fd,&ipaddr,&val,BPF_ANY);
		if (ips!=0){
			printf("ip entry failed");
			return 1;
		}
	}
	printf("\nip_blacklist map has been updated with the blacklist values\n");
	while (fgets(port,sizeof(port),PORTfile) != NULL){
		if (strlen(port)==0) continue;
		port[strcspn(port,"\n")]='\0';
		portnumber =htons((__u16)(atoi(port)));
		ports = bpf_map_update_elem(port_whitelist_fd,&portnumber,&val,BPF_ANY);
		if (ports!=0){
			printf("\nport entry failed\n");
			return 1;
		}
	}
	printf("\nport_whitelist has been updated with the white ports\n");
	// close the files that have the ip address and port numbers
	fclose(IPfile);
	fclose(PORTfile);

	// creating an xdp bpf link
	const char *program = "verify_packet";
	printf("\nChecking and loading the bpf program\n");
	struct bpf_program *prog = bpf_object__find_program_by_name(object,program);
	if (!prog){
		fprintf(stderr,"Error grtting the name of the program");
		return 1;
	}
	printf("\nChecking and creating linker\n");
	struct bpf_link *linker = bpf_program__attach_xdp(prog,interface_number);
	if (!linker){
		fprintf(stderr,"Error making the linker");
		return 1;
	}
	printf("Started and running Successfull");

	// keep the userspace program in sleep while the ebpf code in executing in kernel
	while(keep_running){
		pause();
	}

	// destroy and close the linkers and objects
	bpf_link__destroy(linker);
        bpf_object__close(object);
	return 0;
}
