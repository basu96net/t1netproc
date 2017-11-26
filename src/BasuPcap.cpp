/*
 * BasuPcap.cpp
 *
 *  Created on: Nov 19, 2017
 *      Author: mono
 */
extern int mainSniffex(int argc, char** argv);

extern int mainStartCapture(int argc, char * argv[]);
extern int mainUdpDump(int argc, char* argv[]);
extern int mainListInterface(int argc, char* argv[]);



int main(int argc, char * argv[])
{

	//return mainStartCapture(argc, argv);
	return mainSniffex(argc,  argv);

//	return mainListInterface(argc, argv);
//	return mainUdpDump(argc, argv);


}
