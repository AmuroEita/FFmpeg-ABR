#ifndef tcp_h
#define tcp_h

#include "ip.h"

/* TCP flags */
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECNECHO 0x40 /* ECN Echo */
#define TH_CWR 0x80		/* ECN Cwnd Reduced */
#define TH_AE 0x100		/* AccECN (draft-ietf-tcpm-accurate-ecn;rfc7560) part of L4S (rfc9330) */

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MAXSEG 2
#define TCPOLEN_MAXSEG 4
#define TCPOPT_WSCALE 3	   /* window scale factor (rfc1323) */
#define TCPOPT_SACKOK 4	   /* selective ack ok (rfc2018) */
#define TCPOPT_SACK 5	   /* selective ack (rfc2018) */
#define TCPOPT_ECHO 6	   /* echo (rfc1072) */
#define TCPOPT_ECHOREPLY 7 /* echo (rfc1072) */
#define TCPOPT_TIMESTAMP 8 /* timestamp (rfc1323) */
#define TCPOLEN_TIMESTAMP 10
#define TCPOLEN_TSTAMP_APPA (TCPOLEN_TIMESTAMP + 2) /* appendix A */
#define TCPOPT_CC 11								/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCNEW 12								/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCECHO 13							/* T/TCP CC options (rfc1644) */
#define TCPOPT_SIGNATURE 19							/* Keyed MD5 (rfc2385) */
#define TCPOLEN_SIGNATURE 18
#define TCP_SIGLEN 16  /* length of an option 19 digest */
#define TCPOPT_SCPS 20 /* SCPS-TP (CCSDS 714.0-B-2) */
#define TCPOPT_UTO 28  /* tcp user timeout (rfc5482) */
#define TCPOLEN_UTO 4
#define TCPOPT_TCPAO 29		   /* TCP authentication option (rfc5925) */
#define TCPOPT_MPTCP 30		   /* MPTCP options */
#define TCPOPT_FASTOPEN 34	   /* TCP Fast Open (rfc7413) */
#define TCPOPT_EXPERIMENT2 254 /* experimental headers (rfc4727) */

#define HTTP_PORT 80
#define HTTPS_PORT 443

struct tcphdr
{
	nd_uint16_t th_sport; /* source port */
	nd_uint16_t th_dport; /* destination port */
	nd_uint32_t th_seq;	  /* sequence number */
	nd_uint32_t th_ack;	  /* acknowledgement number */
	nd_uint8_t th_offx2;  /* data offset, rsvd */
	nd_uint8_t th_flags;
	nd_uint16_t th_win; /* window */
	nd_uint16_t th_sum; /* checksum */
	nd_uint16_t th_urp; /* urgent pointer */
};

#define TH_OFF(th) ((GET_U_1((th)->th_offx2) & 0xf0) >> 4)

static inline void
get_cpy_bytes(netdissect_options *ndo, char *dst, const char *p, size_t len)
{
	UNALIGNED_MEMCPY(dst, p, len);
}

#define GET_CPY_BYTES(dst, p, len) get_cpy_bytes(ndo, (char *)(dst), (const char *)(p), len)

#define tcp_get_flags(th) ((GET_U_1((th)->th_flags)) | \
						   ((GET_U_1((th)->th_offx2) & 0x0f) << 8))

#define IPOPT_EOL 0 /* end of option list */
#define IPOPT_NOP 1 /* no operation */

#define IPOPT_RR 7		   /* record packet route */
#define IPOPT_TS 68		   /* timestamp */
#define IPOPT_RFC1393 82   /* traceroute RFC 1393 */
#define IPOPT_SECURITY 130 /* provide s,c,h,tcc */
#define IPOPT_LSRR 131	   /* loose source route */
#define IPOPT_SSRR 137	   /* strict source route */
#define IPOPT_RA 148	   /* router-alert, rfc2113 */

#endif