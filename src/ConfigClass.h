/*
 * ConfigClass.h
 *
 *  Created on: Nov 22, 2017
 *      Author: mono
 */

#ifndef CONFIGCLASS_H_
#define CONFIGCLASS_H_

class ConfigsClass{
public:
	static int CaptureLoopQueue;
	static int MaximumSnapLengthPerPacket;
	static bool ExitOnNonEthernetInterface;
	static bool UseCompiledFilter;
	static bool PrintTcpPayload;
};

extern ConfigsClass configs;

//#define USE_ETH_DATALINK_FILTER (FALSE)

#endif /* CONFIGCLASS_H_ */
