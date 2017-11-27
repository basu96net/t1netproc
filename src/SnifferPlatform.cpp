#include "SnifferPlatform.h"

SnifferPlatform *  pPlt;

int mainSniffex(int argc, char** argv){

	SnifferPlatform plt;
	pPlt = &plt;
	return plt.mainSniffex(argc , argv);
}
void
UpdateConnectionTableCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
 pPlt->UpdateConnectionTable(args, header, packet);
}


//void
//print_payload(const u_char *payload, int len);
//
//void
//print_hex_ascii_line(const u_char *payload, int len, int offset);
//
//void
//print_app_banner(void);
//
//void
//print_app_usage(void);

/*
 * app name/banner
 */
void
SnifferPlatform::print_app_banner(void)
{

//	printf("%s - %s\n", APP_NAME, APP_DESC);
//	printf("%s\n", APP_COPYRIGHT);
//	printf("%s\n", APP_DISCLAIMER);
//	printf("\n");

return;
}

/*
 * print help text
 */
void
SnifferPlatform::print_app_usage(void)
{

	//printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
SnifferPlatform::print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
SnifferPlatform::print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


/*
 * dissect/print packet
 */
void
SnifferPlatform::UpdateConnectionTable(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	char* srcAddr = inet_ntoa(ip->ip_src);
	char* dstAddr = inet_ntoa(ip->ip_dst);

	printf("       From: %s\n", srcAddr);
	printf("         To: %s\n",dstAddr);

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	u_short srcPort = ntohs(tcp->th_sport);
	u_short dstPort = ntohs(tcp->th_dport);

	printf("   Src port: %d\n", srcPort);
	printf("   Dst port: %d\n", dstPort);

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	std::string srcEp;
	std::string dstEp;

	srcEp+= srcAddr;
	srcEp+=":";
	srcEp+= srcPort;


	dstEp+= dstAddr;
	dstEp+=":";
	dstEp+= dstPort;








	std::string smallerEp;
	std::string biggerEp;


	Pipe* pPipe = NULL;

	bool biggerReceivedTheFlags;
	if (srcEp < dstEp){
		biggerReceivedTheFlags = true;
		smallerEp = srcEp;
		biggerEp = dstEp;
	}
	else {
		biggerReceivedTheFlags = false;
		smallerEp = dstEp;
		biggerEp = srcEp;
	}

	std::string lookupKey;

	lookupKey += smallerEp;
	lookupKey += "<->";
	lookupKey += biggerEp;

	PipeMapIt it = ctrl.pipeMap.find(lookupKey);

	if (it!=ctrl.pipeMap.end()){
		pPipe = it->second;
	}else{
		pPipe = new Pipe();
		pPipe->closeCount = 0;
		pPipe->ep1.id = smallerEp;
		pPipe->ep1.updateTime = 0;
		pPipe->ep1.lastFlags.flagByte = 0;
		pPipe->ep2.id = biggerEp;
		pPipe->ep2.updateTime = 0;
		pPipe->ep2.lastFlags.flagByte = 0;
		ctrl.pipeMap[lookupKey] = pPipe;
	}
	Pipe* dstPipe = NULL;


	//sprintf("%s", srcEp.c_str(), )

//	if (tcp->flags.ack ){
//
//	}

if (configs.PrintTcpPayload){
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
}

return;
}
//extern "C"{
//int mainSniffex(int argc, char* argv[]);
//}

int SnifferPlatform::mainSniffex(int argc, char** argv)
{

	char *devName = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = configs.CaptureLoopQueue;			/* number of packets to capture */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		devName = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		devName = pcap_lookupdev(errbuf);
		if (devName == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
		pcap_if_t *alldevs;
		pcap_if_t *dev;
		int inum;
		int i=0;
//		pcap_t *adhandle;
//		char errbuf[PCAP_ERRBUF_SIZE];
//		u_int netmask;
//		char packet_filter[] = "ip and (tcp or udp)";
		struct bpf_program fcode;

		/* Retrieve the device list */
		if(pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for(dev=alldevs; dev; dev=dev->next)
		{
			printf("%d. %s", ++i, dev->name);
			if (dev->description)
				printf(" (%s)\n", dev->description);
			else
				printf(" (No description available)\n");
		}

		if(i==0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}

		printf("Enter the interface number (1-%d):",i);
		scanf("%d", &inum);

		/* Check if the user specified a valid adapter */
		if(inum < 1 || inum > i)
		{
			printf("\nAdapter number out of range.\n");

			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		/* Jump to the selected adapter */
		for(dev=alldevs, i=0; i< inum-1 ;dev=dev->next, i++);

		devName = dev->name;
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(devName, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    devName, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", devName);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(devName, configs.MaximumSnapLengthPerPacket, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", devName, errbuf);
		exit(EXIT_FAILURE);
	}

	if ( configs.ExitOnNonEthernetInterface){
		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", devName);
			exit(EXIT_FAILURE);
		}
	}

	if (configs.UseCompiledFilter){
		/* compile the filter expression */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		/* apply the compiled filter */
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}
	/* now we can set our callback function */
	pcap_loop(handle, num_packets, UpdateConnectionTableCallback, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

//}
