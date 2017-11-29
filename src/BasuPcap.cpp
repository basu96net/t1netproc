/*
 * BasuPcap.cpp
 *
 *  Created on: Nov 19, 2017
 *      Author: mono
 */

#include "timer.h"
#include "SnifferPlatform.h"
extern int TcpRecognizer(int argc, char** argv);

SnifferPlatform *  pPlt;

int TcpRecognizer(int argc, char** argv){

	SnifferPlatform plt;
	pPlt = &plt;
	return plt.StarTcpRegnizer(argc , argv);
}

void
UpdateConnectionTableCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
 pPlt->UpdateConnectionTable(args, header, packet);
}

void timer_handler(void)
{
	pPlt->PrintPipes();
}

int main(int argc, char * argv[])
{
	  if(start_timer(5000, &timer_handler))
	  {
	    return(1);
	  }
	return TcpRecognizer(argc,  argv);
}
