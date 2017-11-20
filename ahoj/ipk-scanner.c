#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>

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

#define BUF_SIZE 64

void change_ip_endian(char *ptr){
	ptr[0] ^= ptr[3];
	ptr[3] ^= ptr[0];
	ptr[0] ^= ptr[3];
	ptr[1] ^= ptr[2];
	ptr[2] ^= ptr[1];
	ptr[1] ^= ptr[2];
}

int addr_count = 0;
char ip[8000];
char mac[12000];

char *interface;
char *output;
FILE *out;
int s = 0;

void sigint(int signum);

void print_ip(unsigned char *addr){
	fprintf(out, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	return;
}

void print_mac(unsigned char *addr){
	fprintf(out, "%02x%02x.%02x%02x.%02x%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return;
}

void print_mapping(){
	out = fopen(output, "w");
	fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fprintf(out, "<devices>\n");
	for(int i = 0; i < addr_count; i++){
		fprintf(out, "\t<host mac=\"");
		print_mac(mac+ i*6);		
		fprintf(out, "\">\n");
		fprintf(out, "\t\t<ipv4>"); 
		print_ip(ip + i*4);
		fprintf(out, "</ipv4>\n");
		fprintf(out, "\t</host>\n");
	}
	fprintf(out, "</devices>\n");
	fclose(out);
	return;
}
// Structure holding arp headder, check out documentation for more information
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

int addrcmp(unsigned char *a, unsigned char *b){
	if(a[0] != b[0]) return 0;
	if(a[1] != b[1]) return 0;
	if(a[2] != b[2]) return 0;
	if(a[3] != b[3]) return 0;
	return 1;
}

void you_should_get_help(){
	printf("Usage: ipk-scanner -i <Interface> -f <output file>\n");
	printf("Have an amazing day and do not forget to smile :]\n");	
}

int main(int argc, char *argv[]) {
	if(argc != 5 || !strcmp(argv[1], "i") || !strcmp(argv[3], "f")){
		you_should_get_help();
		return 1;
	}
	interface = argv[2];
	output = argv[4];
	char cosi0[64];
	void *buffer = (void*)cosi0; // Buffer for Ethernet Frame
	struct ethhdr *eh = (struct ethhdr *)buffer;  // pointer into ethernet frame to headder
	struct arp_headder *ah = (struct arp_headder *)(buffer + 14); // 14 i ethernet headder size... so this points to beggining of ARP request
	pid_t sender; // fork will be called later on...
	unsigned char src_mac[6];    	//our mac
	unsigned char src_ip[4];			// our ip
	unsigned char src_ip_mask[4];	// subnet mask

	struct sockaddr_ll device;   // this will be used to hold information about interface device
	struct ifreq ifr;	// for ioctl calls

	int ifindex = 0;    //Ethernet Interface index
	int length;  //length of received packet
	int sent;		// in case of error...

	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s == -1) {
	perror("socket():");
	exit(1);
	}

	// Interface index
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if (ioctl(s, SIOCGIFINDEX, &ifr) == -1) {
	perror("SIOCGIFINDEX"); exit(1);
	}
	ifindex = ifr.ifr_ifindex;

	// our IP
	if (ioctl(s, SIOCGIFADDR, &ifr) == -1){
	perror("SIOCGIFADDR"); exit(1);	
	}
	memcpy(src_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4 * sizeof (uint8_t));	

	// our MAC
	if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1) {
	perror("SIOCGIFINDEX"); exit(1);
	}
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));	

	// subnet mask
	if(ioctl(s, SIOCGIFNETMASK, &ifr) == -1){
	  perror("SIOCGIFNETMASK"); exit(1);  
	}
	memcpy(src_ip_mask, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4 * sizeof (uint8_t));

	//signal handler
	signal(SIGINT, sigint);

	for(int i = 0; i < 6; i++)	
		eh->h_dest[i] = 0xff;
	memcpy(eh->h_source, src_mac, 6 * sizeof (uint8_t));	
	eh->h_proto = ntohs(0x0806);	// The EtherType for ARP is 0x0806

	ah->arp_hd = ntohs(1); 									//This field specifies the network protocol type. Example: Ethernet is 1.
	ah->arp_pr = ntohs(2048); 							//For IPv4, this has the value 0x0800.
	ah->arp_hdl = 6 * sizeof (uint8_t);			// lenght of mac address is 6 ocets/bytes  
	ah->arp_prl = 4 * sizeof (uint8_t);			// length of ipv4 address is 4 ocets/bits
	ah->arp_op = ntohs(1);									// 1 for request, 2 for reply
	memcpy(ah->arp_sha, src_mac, 6 * sizeof (uint8_t));
	memcpy(ah->arp_spa, src_ip, 4 * sizeof (uint8_t));
	memset(ah->arp_dha, 0, 6*sizeof(uint8_t));		// in arp request this is ignored so im just setting it to 0...
	// Put info about device int device...
	device.sll_family = AF_PACKET;
	device.sll_protocol = ETH_P_IP;
	device.sll_ifindex = ifindex;
	device.sll_hatype = ARPHRD_ETHER;
	device.sll_pkttype = PACKET_OTHERHOST;
	device.sll_halen = ETH_ALEN;
	for(int i = 0; i < 8; i++)
		device.sll_addr[i] = 0xff;

	// sender thread will send requests to all network users and this thread will go through all incomming messages
	sender = fork();
	if(sender == -1){
		perror("fork");
		exit(1);
	}
	if(sender == 0){
		//Evil hacking.. basically just goes through all ip addresses in current network
		// and sends special packet for every one of them...
		unsigned char target_address[4];
		uint32_t *target_addr = (uint32_t*) target_address;
		memcpy(target_addr, src_ip, 4 * sizeof (uint8_t));	
		uint32_t *mask = (uint32_t*)src_ip_mask;
		uint32_t max_ip = *target_addr | (~(*mask));
		// because network indians are just evil...
		change_ip_endian(target_address);		
		change_ip_endian((char *)mask);		
		change_ip_endian((char *)&max_ip);		

		for(*target_addr = *target_addr & *mask; *target_addr < max_ip; *target_addr = *target_addr + ((uint32_t)1 )){
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
	// cosi is a buffer... i do not acces it directly and i ran out of ideas how to call different buffers
	// it is another buffer for ethernet packet
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
	  exit(1);
	}
	if(htons(recv_eh->h_proto) == 0x806){
			if(htons(recv_ah->arp_op)!= 2)
				continue;			
			// Every address only once
			int exists = 0;
			for(int i = 0; i < addr_count; i++){
				if(addrcmp(ip + 4*i, recv_ah->arp_spa)){
					exists = 1;
					break;							
				}
			}
			if(exists)
				continue;
			memcpy(ip + addr_count*4, recv_ah->arp_spa, 4);
			memcpy(mac + addr_count*6, recv_ah->arp_sha, 6);
			addr_count ++;
		}
	}
	print_mapping();
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
	
	print_mapping();
  exit(0);
}
