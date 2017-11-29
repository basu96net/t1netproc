/*
 * SnifferPlatform.h
 *
 *  Created on: Nov 27, 2017
 *      Author: mono
 */

#ifndef SNIFFERPLATFORM_H_
#define SNIFFERPLATFORM_H_



#include "stdinclude.h"

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#include "DataStructs.h"


class SnifferPlatform{
protected:
	CaptureControl ctrl;

	void ClearScreen();
	const char *State2Str(const PipeState state);
	std::string  GetStateString(PipeState state);

public:

	void PrintPipes();
void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);



/*
 * print packet payload data (avoid printing binary data)
 */


/*
 * dissect/print packet
 */

void
UpdateConnectionTable(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int StarTcpRegnizer(int argc, char** argv);

};

#endif /* SNIFFERPLATFORM_H_ */
