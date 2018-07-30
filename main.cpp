#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void usage() 
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void read_packet(uint8_t *packet, uint8_t len)
{
	struct ethhdr *ethhdr;
	struct ether_addr *dest, *src;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	uint8_t *data;
	uint16_t iphdr_len;
	uint32_t idx, sip, dip, data_size;

	idx = 0;

	// read frame header data
	ethhdr = (struct ethhdr *)(packet+idx);
	idx += sizeof(struct ethhdr);
	if ( htons(ethhdr->h_proto) == ETH_P_ARP )
		return;	
	// read packet header data
	iphdr = (struct iphdr *)(packet+idx);
	idx += sizeof(struct iphdr);
	if ( iphdr->protocol != IPPROTO_TCP )
		return;

	dest = (struct ether_addr *)ethhdr->h_dest;
	src  = (struct ether_addr *)ethhdr->h_source;
	iphdr_len = iphdr->ihl*4; // size of ip header
	// read segment header data
 	tcphdr = (struct tcphdr *)(packet+idx);
	idx += sizeof(struct tcphdr);
	// read data 
	data_size = len - idx;
	if ( data_size > 16 )
		data_size = 16;
	data = (uint8_t *)malloc( data_size );
	data = (uint8_t *)(packet+idx);

	printf("[+] Captured IP Packet\n");
	printf("DEST MAC : %s\n", ether_ntoa(dest));
	printf("SRC  MAC : %s\n", ether_ntoa(src));
	printf("SRC   IP : %s\n", inet_ntoa(*(struct in_addr *)&iphdr->saddr));
	printf("DEST  IP : %s\n", inet_ntoa(*(struct in_addr *)&iphdr->daddr));
	printf("------DATA------\n");
	for ( int i = 0; i < data_size; i++ )
		printf("%02x ", data[i]);
	printf("\n\n");
}

int main(int argc, char* argv[]) 
{
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	int len, idx;
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		read_packet((uint8_t *)packet, (uint8_t)header->caplen);
	}

	pcap_close(handle);
	return 0;
}
