#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#define BUF_SIZE 64
#include <ifaddrs.h>
// ----------- globals
char *interface = NULL; 	// chosen interface
int tcpflag = 0;				// scan TCP
int udpflag = 0;				// scan UDP
int port = -1;					// port to scan
int wait = 0;					// wait time before port is considered closed
struct in_addr network;		// network to scan
int netmask = 0;				// mask of the network to scan
int addr_count = 0;			// how many ip's are in specified network
char ip_addresses[80000];	// array to hold dem ip's
char mac[12000];			// array of mac addresses, well see whether i need it or not
int s = 0;						// happy little socket / for arp stuff
int p = 0;						// another happy little socket  / for icmp stuff
unsigned char src_ip[4];	// our ip address
unsigned char src_mac[6];// our mac should we need it
int pid = 0;
int ifindex = 0;

//--------------------



struct __attribute__((packed)) arp_headder{
	unsigned short arp_hd;
	unsigned short arp_pr;
	unsigned char arp_hdl;
	unsigned char arp_prl;
	unsigned short arp_op;
	unsigned char arp_sha[6];
	unsigned char arp_spa[4];
	unsigned char arp_dha[6];
	unsigned char arp_dpa[4];
};

#define PACKETSIZE	64
struct icmp_packet{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

void change_ip_endian(char *ptr){
	ptr[0] ^= ptr[3];
	ptr[3] ^= ptr[0];
	ptr[0] ^= ptr[3];
	ptr[1] ^= ptr[2];
	ptr[2] ^= ptr[1];
	ptr[1] ^= ptr[2];
}
void sigint(int signum);

void print_ip(unsigned char *addr){
	fprintf(stdout, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	return;
}

int addrcmp(unsigned char *a, unsigned char *b){
	if(a[0] != b[0]) return 0;
	if(a[1] != b[1]) return 0;
	if(a[2] != b[2]) return 0;
	if(a[3] != b[3]) return 0;
	return 1;
}

void get_help(){
	printf("Usage \n");
	printf("isamon [-h] [-i <interface>] [-t] [-u] [-p <port>] [-w <ms>] -n <net_address/mask> \n");
	printf("\t -h --help -- zobrazí nápovědu \n");
	printf("\t -i --interface <interface> -- rozhraní na kterém bude nástroj scanovat \n");
	printf("\t -n --network <net_address/mask> -- ip adresa síťe s maskou definující rozsah pro scanování \n");
	printf("\t -t --tcp -- použije TCP \n");
	printf("\t -u --udp -- použije UDP \n");
	printf("\t -p --port <port> -- specifikace scanovaného portu, pokud není zadaný, scanujte celý rozsah \n");
	printf("\t -w --wait <ms> -- dodatečná informace pro Váš nástroj jaké je maximální přípustné RTT \n");
}

int check_network(struct in_addr *network, int netmask){
	int net = (int) network->s_addr;
	print_ip((char *) &net);
	return 0;
}

int get_args(int argc, char *argv[]){
	int option;
	char * mask = NULL;
	int tmp;
	while((option = getopt(argc, argv, "hi:tup:w:n:")) != -1){
		switch(option){
			case 'h':
			  get_help();
			  return 0;
			case 'i':
				interface = optarg;
			break;
			case 't':
				tcpflag = 1;
			break;
			case 'u':
				udpflag = 1;
			break;
			case 'p':
				port = strtol(optarg, 0, 10);
				if(errno == ERANGE){
					fprintf(stderr, "Port integer OVERFLOW... seriously?!\n");
					return 1;
				}
				if(port < 0){
					fprintf(stderr, "Did you really just set negative port number?... Sorry, cant help you...\n");
					return 1;
				}
				if(port > 65535){
					fprintf(stderr, "Maximum allowed port number is 65535, sorry.\n");
					return 1;
				}
				break;
			case 'w':
				wait = strtol(optarg, 0, 10);
				if(errno == ERANGE){
					fprintf(stderr, "wait period overflow... for some weird reason...\n");
					return 1;
				}
				if(port < 0){
					fprintf(stderr, "im not a time machine, set a positive waiting period please\n");
					return 1;
				}
				break;
			case 'n':
				mask = strstr(optarg, "/");
				if(mask == NULL){
					fprintf(stderr, "netmask not found :(\n");
				}
				*mask = 0;
				if(!inet_aton(optarg, &network)){
					fprintf(stderr, "invalid address :(\n");
				}
				if(errno == ERANGE){
					fprintf(stderr, "mask integer overflow... BUT WHY?!\n");
					return 1;
				}
				if(tmp < 0){
					fprintf(stderr, "... i mean... why?! negative network mask number?\n");
					return 1;
				}
				if(tmp > 31){
					fprintf(stderr, "network mask must be smaller than 32 i belive... \n");
					return 1;
				}
				if(mask != NULL){
					tmp =  strtol(mask+1, 0, 10);
					for(int i = 0; i < tmp; i++){
						netmask |= 1 << (31-i);
					}
				}
				if(check_network(&network, tmp)){
					fprintf(stderr, "Invalid network!\n");
					return 1;
				}
				break;
			default:
				printf("Usage: \nisamon [-h] [-i <interface>] [-t] [-u] [-p <port>] [-w <ms>] -n <net_address/mask>\n");
				return 0;
			break;
		}
	}
	if(mask == NULL){
		fprintf(stderr, "-n is mantadory!\n");
		return 1;
	}
	return 0;
}

int spam_arp(struct in_addr *net){
	struct sockaddr_ll device;
	
	char arp_packet_buffer[64];
	void *buffer = (void*)arp_packet_buffer;
	struct ethhdr *eh = (struct ethhdr *)buffer; 
	struct arp_headder *ah = (struct arp_headder *)(buffer + 14);
	
	for(int i = 0; i < 6; i++)	
		eh->h_dest[i] = 0xff;
	memcpy(eh->h_source, src_mac, 6 * sizeof (uint8_t));	
	ah->arp_hd = ntohs(1); 									//This field specifies the network protocol type. Example: Ethernet is 1.
	ah->arp_pr = ntohs(2048); 							//For IPv4, this has the value 0x0800.
	ah->arp_hdl = 6 * sizeof (uint8_t);			// lenght of mac address is 6 ocets/bytes  
	ah->arp_prl = 4 * sizeof (uint8_t);			// length of ipv4 address is 4 ocets/bits
	ah->arp_op = ntohs(1);									// 1 for request, 2 for reply
	memcpy(ah->arp_sha, src_mac, 6 * sizeof (uint8_t));
	memcpy(ah->arp_spa, src_ip, 4 * sizeof (uint8_t));
	memset(ah->arp_dha, 0, 6*sizeof(uint8_t));		// in arp request this is ignored so im just setting it to 0...
	
	device.sll_family = AF_PACKET;
	device.sll_protocol = ETH_P_IP;
	device.sll_ifindex = ifindex;
	device.sll_hatype = ARPHRD_ETHER;
	device.sll_pkttype = PACKET_OTHERHOST;
	device.sll_halen = ETH_ALEN;
	for(int i = 0; i < 8; i++)
		device.sll_addr[i] = 0xff;
	
	unsigned char target_address[4];
	uint32_t *target_addr = (uint32_t*) target_address;
	memcpy(target_addr, src_ip, 4 * sizeof (uint8_t));	
	uint32_t *mask = (uint32_t*)&netmask;
	uint32_t max_ip = *target_addr | (~(*mask));
	// because network indians are just evil...
	change_ip_endian(target_address);		
	change_ip_endian((char *)mask);		
	change_ip_endian((char *)&max_ip);		
	int sent = 0;
	for(*target_addr = *target_addr & netmask; *target_addr < max_ip; *target_addr = *target_addr + ((uint32_t)1 )){
		change_ip_endian(target_address);
		memcpy(ah->arp_dpa, target_addr, 4 * sizeof (uint8_t));
		if((sent = sendto(s, buffer, BUF_SIZE, 0, (struct sockaddr*)&device, sizeof(device))) == -1){
			perror("Send:");		
		}
		change_ip_endian(target_address);
		usleep(1000);
	}
	exit(EXIT_SUCCESS);
}


int get_arp_responses(){
	int length;
	char cosi[64];
	void* receaved = (void *)cosi;
	struct ethhdr *recv_eh = (struct ethhdr *)receaved; 
	struct arp_headder *recv_ah = (struct arp_headder *)(receaved + 14);
	// loop for 5 seconds
	time_t start = time(NULL);
	time_t end = start + 5;
	while(start < end){
		start = time(NULL);
		length = recvfrom(s, receaved, BUF_SIZE, 0, NULL, NULL);
		if (length == -1){
			perror("recvfrom():");
			return 1;
		}
		if(htons(recv_eh->h_proto) == 0x806){
			if(htons(recv_ah->arp_op)!= 2)
				continue;			
			// Every address only once
			int exists = 0;
			for(int i = 0; i < addr_count; i++){
				if(addrcmp(ip_addresses + 4*i, recv_ah->arp_spa)){
					exists = 1;
					break;							
				}
			}
			if(exists)
				continue;
			memcpy(ip_addresses + addr_count*4, recv_ah->arp_spa, 4);
			memcpy(mac + addr_count*6, recv_ah->arp_sha, 6);
			addr_count ++;
		}
	}
	return 0;
}

struct protoent *proto=NULL;

unsigned short checksum(void *b, int len)
{	unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

int spam_icmp(struct in_addr *net){
	unsigned char target_address[4];
	uint32_t *target_addr = (uint32_t*) target_address;
	memcpy(target_addr, src_ip, 4 * sizeof (uint8_t));	
	
	uint32_t *mask = (uint32_t*)&netmask;
	uint32_t max_ip = *target_addr | (~(*mask));
	
	struct hostent *hname;
	struct sockaddr_in addr;
	const int val=255;
	
	struct icmp_packet pckt;
	bzero(&pckt, sizeof(pckt));
	pckt.hdr.type = ICMP_ECHO;
	pckt.hdr.un.echo.id = pid;
	pckt.hdr.un.echo.sequence = 1;
	pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
	
	proto = getprotobyname("ICMP");
	p = socket(PF_INET, SOCK_RAW, proto->p_proto);
	
	
	if(p < 0){
		perror("icmp spammer error - socket:");
		return 1;
	}
	
	if ( setsockopt(p, SOL_IP, IP_TTL, &val, sizeof(val)) != 0)
		perror("Error, cant set TTL");
	if ( fcntl(p, F_SETFL, O_NONBLOCK) != 0 )
		perror("Request nonblocking I/O");
	
	change_ip_endian(target_address);		
	change_ip_endian((char *)mask);		
	change_ip_endian((char *)&max_ip);		
	
	for(*target_addr = *target_addr & *mask; *target_addr < max_ip; *target_addr = *target_addr + ((uint32_t)1 )){
		change_ip_endian(target_address);
		
		hname = gethostbyaddr(target_addr, sizeof(struct in_addr), AF_INET);
		bzero(&addr, sizeof(addr));
		addr.sin_family = hname->h_addrtype;
		addr.sin_port = 0;
		addr.sin_addr.s_addr = *(long*)hname->h_addr;
		
		if ( sendto(p, &pckt, sizeof(pckt), 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0 )
			perror("sendto");
		
		change_ip_endian(target_address);
		usleep(1000);
	}

	return 0;
}


int get_icmp_responses(struct in_addr *net){
	int sock;
	struct sockaddr_in addr;
	unsigned char buffer[1024];

	sock = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if ( sock < 0 )
	{
		perror("socket");
		exit(0);
	}
	while(1){	
		int len, max_len = sizeof(addr);

		bzero(buffer, sizeof(buffer));
		len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &max_len);
		
		struct iphdr *ip = (struct iphdr *)buffer;
		struct icmphdr *icmp = (struct icmphdr *)(buffer+ip->ihl*4);
		int exists = 0;
		for(int i = 0; i < addr_count; i++){
			if(addrcmp(ip_addresses + 4*i, (unsigned char *)&ip->saddr)){
				exists = 1;
				break;							
			}
		}
		if(exists)
			continue;
		memcpy(ip_addresses + addr_count*4, &ip->saddr, 4);
		addr_count ++;
	}
	return 0;
}

uint32_t get_our_network(int *mask){
	struct ifreq ifr;	// for ioctl calls
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if (ioctl(s, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX"); 
		*mask = -1;
		return 0;
	}
	ifindex = ifr.ifr_ifindex;
	if (ioctl(s, SIOCGIFADDR, &ifr) == -1){
		perror("SIOCGIFADDR"); 
		*mask = -1;
		return 0;
	}
	memcpy(src_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4 * sizeof (uint8_t));	
	
	if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		*mask = -1;
		return 0;
	}
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));	
	
	if(ioctl(s, SIOCGIFNETMASK, &ifr) == -1){
		perror("SIOCGIFNETMASK");
		*mask = -1;
		return 0;
	}
	memcpy(mask, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4 * sizeof (uint8_t)); // ugly i know... dont care
	
	return (*((int*)src_ip))|*mask;
}

int check_open_ports(struct in_addr *address){
	return 0;
}

int main(int argc, char *argv[]) {
	if(get_args(argc, argv)) return 1;
	
		// our ip
	pid_t spammer;
	unsigned char src_ip_mask[4];	// subnet mask

	struct sockaddr_ll device;			// this will be used to hold information about interface device
	struct ifreq ifr;						// for ioctl calls
	/*
	char eth_frame[64];					//will be addressed only through pointers
	void *buffer = (void*)eth_frame;
	struct ethhdr *eh = (struct ethhdr *)buffer; 	// start of ethernet headder
	struct arp_headder *ah = (struct arp_headder *)(buffer + 14); // then there is ARP headder
	*/
	int our_mask;
	unsigned char our_network[4];	
	uint32_t *	pomocna = (uint32_t *) our_network;
	
	struct ifaddrs *addrs,*tmp;
	pid = getpid();
	getifaddrs(&addrs);
	tmp = addrs;
	
	if (s == -1) {
		perror("socket(): ");
		netmask = -1;
		return 0;
	}
	
	int ifflag = 0;
	if(interface != NULL){
		ifflag = 1;
	}
	while (tmp){
		*pomocna = get_our_network(&our_mask);
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET){
			if(ifflag && strcmp(tmp->ifa_name, interface)){
				continue;
			}
			interface = tmp->ifa_name;
		}
		
		spammer = fork();
		if(spammer == -1){
			perror("fork");
			freeifaddrs(addrs);
			exit(1);
		}
		if(spammer == 0){
			if(addrcmp(our_network, (unsigned char *)&network) && addrcmp((unsigned char*)&netmask, (unsigned char*)&our_mask)){
				spam_arp(&network);
			}
			else{
				spam_icmp(&network);
			}
			// maybe memory leak, check 
		}
		
		
		if(addrcmp(our_network, (unsigned char *)&network) && addrcmp((unsigned char*)&netmask, (unsigned char*)&our_mask)){
			get_arp_responses();
		}
		else{
			get_icmp_responses((struct in_addr *)ip_addresses);
		}
		for(int i = 0; i < addr_count; i++){
			printf("adresa...");
			check_open_ports((struct in_addr *)(ip_addresses + 4 * i));  // tady budou dalsi vypisy
		}
		bzero(ip_addresses, sizeof(ip_addresses));
		bzero(mac, sizeof(mac));
		addr_count = 0;
		tmp = tmp->ifa_next;
		close(s);
	}
	
	freeifaddrs(addrs);
}


void sigint(int signum) {
	struct ifreq ifr;

	if (s == -1)
	return;

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	ioctl(s, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags &= ~IFF_PROMISC;
	ioctl(s, SIOCSIFFLAGS, &ifr);
	close(s);

	exit(0);
}
