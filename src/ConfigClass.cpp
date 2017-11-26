/*
 * Config.c
 *
 *  Created on: Nov 22, 2017
 *      Author: mono
 */


#include "ConfigClass.h"

ConfigsClass configs;

int ConfigsClass::CaptureLoopQueue = 0;
int ConfigsClass::MaximumSnapLengthPerPacket=1518;
bool ConfigsClass::ExitOnNonEthernetInterface = false;
bool ConfigsClass::UseCompiledFilter = true;
bool ConfigsClass::PrintTcpPayload = false;
