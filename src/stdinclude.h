#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <strings.h>

#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <vector>

#include "winsock2.h"

//#include "interface.h"

#ifndef WPCAP
#define WPCAP
#warning You should include WPCAP in your preprocessor definitions
#endif




#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#warning You should include HAVE_REMOTE in your preprocessor definitions
#endif



#include "pcap.h"

#include "ConfigClass.h"
