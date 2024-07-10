#ifndef ip_h
#define ip_h

#include "netdissect.h"

typedef unsigned char nd_ipv4[4];
typedef unsigned char nd_ipv6[16];

struct ip {
	nd_uint8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	((GET_U_1((ip)->ip_vhl) & 0xf0) >> 4)
#define IP_HL(ip)	(GET_U_1((ip)->ip_vhl) & 0x0f)
	nd_uint8_t	ip_tos;		/* type of service */
	nd_uint16_t	ip_len;		/* total length */
	nd_uint16_t	ip_id;		/* identification */
	nd_uint16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* don't fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	nd_uint8_t	ip_ttl;		/* time to live */
	nd_uint8_t	ip_p;		/* protocol */
	nd_uint16_t	ip_sum;		/* checksum */
	nd_ipv4		ip_src,ip_dst;	/* source and dest address */
};

struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			nd_uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			nd_uint16_t ip6_un1_plen;	/* payload length */
			nd_uint8_t  ip6_un1_nxt;	/* next header */
			nd_uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		nd_uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	nd_ipv6 ip6_src;	/* source address */
	nd_ipv6 ip6_dst;	/* destination address */
};

#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt

#define IN6ADDRSZ   16   /* IPv6 T_AAAA */

#define INT16SZ     2   

#endif