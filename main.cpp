#include <pcap.h>
#include <stdio.h>

void usage() 
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int readBytes(char* packet, int* idx)
{
	int res;
	res = packet[*idx];
	(*idx)++;

	return (unsigned char)res;
}

int readShorts(char* packet, int* idx)
{
	int res;
	//TODO : IDX+1 OUT OF BOUND CHECK
	res = readBytes(packet, idx) * 0x100 + readBytes(packet, idx);
	
	return res;
}

void skipBytes(int skip, int* idx)
{
	(*idx) += skip;
}

void scan_packet(char* packet, int* idx)
{
	int dst_mac[6], src_mac[6], packet_type, trans_type, src_ip[4], dst_ip[4], src_port, dst_port, i, skip;
	(*idx) = 0;

	// Destination MAC Addr
	for ( i = 0; i < 6; i++ )
		dst_mac[i] = readBytes(packet, idx);
	// Source MAC Addr
	for ( i = 0; i < 6; i++ )
		src_mac[i] = readBytes(packet, idx);

	// Packet Type : ipv4, arp
	packet_type = readShorts(packet, idx);

	// SKIP. FIXED VALUE
	skipBytes(9, idx); // FIX

	/* Filter IPv4 && TCP */
	skip = 0;
	switch( packet_type )
	{
		case 0x800: // ipv4
			skip = 2;
			break;
		//case 0x806: // arp
		//case 0x86dd: // ipv6
		default:
			return; // CHECK ONLY IPV4
	}
	trans_type = readBytes(packet, idx);
	if ( trans_type != 0x6 ) // CEHCK ONLY TCP
		return;

	// SKIP.
	skipBytes(skip, idx); // CHANGED BY packet_type.

	// Source IP Addr
	for ( i = 0; i < 4; i++ )
		src_ip[i] = readBytes(packet, idx);
	// Destination IP Addr
	for ( i = 0; i < 4; i++ )
		dst_ip[i] = readBytes(packet, idx);

	// Source Port Addr
	src_port = readShorts(packet, idx);
	// Destination Port Addr
	dst_port = readShorts(packet, idx);

	/* print all */
	printf("#########################\n");

	printf("[*] dst_mac : %02x", dst_mac[0]);
	for ( i = 1; i < 6; i++ )
		printf(":%02x", dst_mac[i]);
	printf("\n");

	printf("[*] src_mac : %02x", src_mac[0]);
	for ( i = 1; i < 6; i++ )
		printf(":%02x", src_mac[i]);
	printf("\n");

	printf("[*] packet_type : 0x%x\n", packet_type);
	printf("[*] trans_type : 0x%x\n", trans_type);

	printf("[*] src_ip : %d", src_ip[0]);
	for ( i = 1; i < 4; i++ )
		printf(".%d", src_ip[i]);
	printf("\n");

	printf("[*] dst_ip : %d", dst_ip[0]);
	for ( i = 1; i < 4; i++ )
		printf(".%d", dst_ip[i]);
	printf("\n");

	printf("[*] src_port : %d\n", src_port);
	printf("[*] dst_port : %d\n", dst_port);
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
		scan_packet((char *)packet, &idx);
	}

	pcap_close(handle);
	return 0;
}
