/*
 * DataStructs.h
 *
 *  Created on: Nov 19, 2017
 *      Author: mono
 */

#ifndef DATASTRUCTS_H_
#define DATASTRUCTS_H_

#include "stdinclude.h"

/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
        //begin of options
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

union tcp_flags{

    u_char fin :1; //Finish Flag
    u_char syn :1; //Synchronise Flag
    u_char rst :1; //Reset Flag
    u_char psh :1; //Push Flag
    u_char ack :1; //Acknowledgement Flag
    u_char urg :1; //Urgent Flag

    u_char ecn :1; //ECN-Echo Flag
    u_char cwr :1; //Congestion Window Reduced Flag

};

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

typedef struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        //u_char  th_offx2;               /* data offset, rsvd */


        u_char ns :1; //Nonce Sum Flag Added in RFC 3540.
        u_char reserved_part1:3; //according to rfc
        u_char th_offx2:4; /*The number of 32-bit words in the TCP header.

        This indicates where the data begins.
        The length of the TCP header is always a multiple
        of 32 bits.*/
#define TH_OFF(th)      (((th)->th_offx2 & 0x0f))
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

        tcp_flags flags;
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
}sniff_tcp;


typedef enum PipeState {
  CLOSED = 0,
  LISTEN,
  SYN_SENT,
  SYN_RCVD,
  ESTABLISHED,
  CLOSE_WAIT,
  LAST_ACK,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSING,
  TIME_WAIT,
  LAST_STATE
} PipeState;

typedef struct Pipe{
	std::string pipeName;
	tcp_flags s2d;
	tcp_flags d2s;
	PipeState state;
	int closeCount;
}Pipe;

typedef struct CaptureControl{
	std::map <std::string , Pipe&> m;
}CaptureControl;

//typedef std::hashma PipeList;
#endif /* DATASTRUCTS_H_ */
