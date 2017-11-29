#include "SnifferPlatform.h"

extern void
UpdateConnectionTableCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);



std::stringstream printMacToStream(const u_char MACData[])
{
	std::stringstream os;

    char oldFill = os.fill('0');

    os  << std::hex << static_cast<unsigned int>(MACData[0]);
    for (u_int i = 1; i < 6; ++i) {
        os << '-' <<  std::hex << static_cast<unsigned int>(MACData[i]);
    }

    os.fill(oldFill);
    return os;
}

/*
 * dissect/print packet
 */
void
SnifferPlatform::UpdateConnectionTable(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{


	static int count = 0;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	count++;

	/* define Ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	std::stringstream srcAddr;
	std::stringstream dstAddr;

	srcAddr << inet_ntoa(ip->ip_src);
	dstAddr << inet_ntoa(ip->ip_dst);



	std::cout<<"src="<<srcAddr.str()
			<<" ["
			<<printMacToStream(ethernet->ether_shost).str()<<"]"
			<<" dst="<<dstAddr.str()
			<<" ["<<printMacToStream(ethernet->ether_dhost).str()<<"]"
			<<std::endl;

	if (IPPROTO_TCP != ip->ip_p )
		return;

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

	size_tcp = TH_OFF(tcp)*4;

	if (size_tcp < 20) {
		return;
	}

	std::string smallerEp;
	std::string biggerEp;
	bool smallerSentTheFlags;

	{
		u_short srcPort = ntohs(tcp->th_sport);
		u_short dstPort = ntohs(tcp->th_dport);


		/* define/compute tcp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

		/* compute tcp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

		std::stringstream srcEpStream;
		std::stringstream dstEpStream;

		srcEpStream << srcAddr.str() << ":" << srcPort;

		dstEpStream << dstAddr.str() << ":" << dstPort;


		std::string srcEp (srcEpStream.str());
		std::string dstEp(dstEpStream.str());








		if (srcEp < dstEp){
			smallerSentTheFlags = true;
			smallerEp = srcEp;
			biggerEp = dstEp;
		}
		else {
			smallerSentTheFlags = false;
			smallerEp = dstEp;
			biggerEp = srcEp;
		}
	}



	std::stringstream lookupKeyStream;
	lookupKeyStream << smallerEp <<"\t<->\t" << biggerEp;

	std::string lookupKey (lookupKeyStream.str());
	std::cout<<"Lookup:"<<lookupKey<<" smaller:"<<smallerSentTheFlags;


	Pipe* pPipe = NULL;
	EndpointInfo* pActiveEp;
	EndpointInfo* pPartyEp;
	{
		PipeMapIt it = ctrl.pipeMap.find(lookupKey);

		if (it!=ctrl.pipeMap.end()){
			//std::cout <<"Continue Recognizing "<<lookupKey<<std::endl;

			pPipe = it->second;
			if (smallerSentTheFlags){
				pActiveEp = &pPipe->ep1;
				pPartyEp = &pPipe->ep2;
			}else { /* source endpoint in ip datagram is the second stored item in pipe */
				pActiveEp = &pPipe->ep2;
				pPartyEp = &pPipe->ep1;
			}

		}else{
			pPipe = new Pipe();
			pPipe->closeCount = 0;

			pPipe->state = PipeState::RECOGNIZING;

			pPipe->ep1.id = smallerEp;
			pPipe->ep2.id = biggerEp;

			if (smallerSentTheFlags){
				pActiveEp = &pPipe->ep1;
				pPartyEp = &pPipe->ep2;

			}else{
				pActiveEp = &pPipe->ep2;
				pPartyEp = &pPipe->ep1;

			}
		}
		ctrl.pipeMap[lookupKey] = pPipe;
		//std::cout <<"Begin Recognizing "<<lookupKey<<std::endl;

	}

	tcp_flags curFlags = tcp->flags;
	tcp_flags prevFlags = pActiveEp->lastFlags;

	pActiveEp->updateTime = time(0);
	pActiveEp->lastFlags = curFlags;
	pActiveEp->everFlags.flagByte = prevFlags.flagByte | curFlags.flagByte;
	pActiveEp->hasFlas = true;


	PipeState pipeState = pPipe->state;



	if ( pActiveEp->lastFlags.flagBits.syn && !pActiveEp->lastFlags.flagBits.ack){
		if (smallerSentTheFlags){
			pipeState = PipeState::SYN_SENT;
		}else{
			pipeState = PipeState::SYN_RCVD;
		}

	}else 	if ( pActiveEp->lastFlags.flagBits.syn && pActiveEp->lastFlags.flagBits.ack){
		pipeState = PipeState::ESTABLISHED;
	}
	else  	if ( pActiveEp->lastFlags.flagBits.fin && !pActiveEp->lastFlags.flagBits.ack){
		if (smallerSentTheFlags){
			if (PipeState::FIN_WAIT_1 == pipeState){
				pipeState = PipeState::CLOSE_WAIT;
			}else{
				pipeState = PipeState::FIN_WAIT_2;
			}
		}else{
			if (PipeState::FIN_WAIT_2 == pipeState){
				pipeState = PipeState::CLOSE_WAIT;
			}else{
				pipeState = PipeState::FIN_WAIT_1;
			}
		}

	}else  	if ( pActiveEp->lastFlags.flagBits.fin && pActiveEp->lastFlags.flagBits.ack){
		pipeState =PipeState::CLOSED;
	}
	else
	{
		pipeState = PipeState::ESTABLISHED;
	}

	pPipe->state = pipeState;



//PrintPipes(); //update connection state after each reception

return;
}
//extern "C"{
//int mainSniffex(int argc, char* argv[]);
//}


int SnifferPlatform::StarTcpRegnizer(int argc, char** argv)
{




	char *devName = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = configs.CaptureLoopQueue;			/* number of packets to capture */



	/* check for capture device name on command-line */
	if (argc == 2) {
		devName = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
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
//	printf("Device: %s\n", devName);
//	printf("Number of packets: %d\n", num_packets);
//	printf("Filter expression: %s\n", filter_exp);

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

	std::cout <<std::endl<<"Recognition session Completed.\n"<<std::endl;

return 0;
}


void SnifferPlatform::ClearScreen(){
	system("cls");
	std::cout << "EndPoint-1"<<"\t\t\t"<<"EndPoint-2"<<"\t\t"<<"Status"<< std::endl;

}


void SnifferPlatform::PrintPipes(){
	PipeMapIt it = ctrl.pipeMap.begin();

	if (it!=ctrl.pipeMap.end()){
		ClearScreen();

	}
	for (; it != ctrl.pipeMap.end(); it++ )
	{
		std::string pipeKey = it->first;
		Pipe *pPipe =  it->second;
	    std::cout << pPipe->ep1.id <<"\t<=>"<<pPipe->ep2.id<< "\t\t" << GetStateString(pPipe->state)
	              << std::endl ;
	}

}


#define VAR_NAME_HELPER(name) #name
#define VAR_NAME(x) VAR_NAME_HELPER(x)

#define CHECK_STATE_STR(x) case(x):return VAR_NAME(x);

const char * SnifferPlatform::State2Str(const PipeState state)
{
  switch(state)
  {
    CHECK_STATE_STR(CLOSED);
    CHECK_STATE_STR(LISTEN);
    CHECK_STATE_STR(SYN_SENT);
    CHECK_STATE_STR(SYN_RCVD);
    CHECK_STATE_STR(ESTABLISHED);
    CHECK_STATE_STR(CLOSE_WAIT);
    CHECK_STATE_STR(LAST_ACK);
    CHECK_STATE_STR(FIN_WAIT_1);
    CHECK_STATE_STR(FIN_WAIT_2);
    CHECK_STATE_STR(CLOSING);
    CHECK_STATE_STR(TIME_WAIT);
    CHECK_STATE_STR(RECOGNIZING);
    default:
      return "Invalid";
  }
}

std::string SnifferPlatform::GetStateString(PipeState state){
	const char * str = State2Str(state);
	std::string ret (str);
	return ret;
}

//}
