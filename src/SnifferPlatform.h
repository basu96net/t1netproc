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
	std::map<std::string, int> endPointMap;

public:

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);


/*
 * print packet payload data (avoid printing binary data)
 */


/*
 * dissect/print packet
 */

void
UpdateConnectionTable(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int mainSniffex(int argc, char** argv);

};

#endif /* SNIFFERPLATFORM_H_ */
