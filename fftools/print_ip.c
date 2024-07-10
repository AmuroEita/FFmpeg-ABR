#include "netdissect.h"
#include "utils.h"

typedef unsigned char nd_uint8_t[1];
typedef unsigned char nd_ipv4[4];

#define IPPROTO_IPV4	    4
#define	IPPROTO_TCP		    6
#define	IPPROTO_UDP		    17
#define IPPROTO_IPV6	    41
#define IPPROTO_ETHERNET	143

const struct tok ipproto_values[] = {
    { IPPROTO_IPV4, "IPIP" },
    { IPPROTO_TCP, "TCP" },
    { IPPROTO_UDP, "UDP" },
    { IPPROTO_IPV6, "IPv6" },
    { IPPROTO_ETHERNET, "Ethernet" },
    { 0, NULL }
};

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

struct cksum_vec {
	const uint8_t	*ptr;
	int		len;
};

#define IP_RES 0x8000

static inline const char *
get_ipaddr_string(netdissect_options *ndo, const char *p)
{
        return ipaddr_string(ndo, p);
}

#define GET_IPADDR_STRING(p) get_ipaddr_string(ndo, (const u_char *)(p))

static const struct tok ip_frag_values[] = {
    { IP_MF,        "+" },
    { IP_DF,        "DF" },
    { IP_RES,       "rsvd" }, /* The RFC3514 evil ;-) bit */
    { 0,            NULL }
};

void
ip_demux_print(netdissect_options *ndo,
	       const char *bp,
	       int length, u_int ver, int fragmented, int ttl_hl,
	       uint8_t nh, const char *iph)
{
	int advance;
	const char *p_name;

	advance = 0;

again:
	switch (nh) {

	case IPPROTO_TCP:
		tcp_print(ndo, bp, length, iph, fragmented);
		break;

	case IPPROTO_ETHERNET:
		if (ver == 6)
			ether_print(ndo, bp, length, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
		else {
			ND_PRINT("[%s requires IPv6]",
				 tok2str(ipproto_values,"unknown",nh));
			nd_print_invalid(ndo);
		}
		break;

	case IPPROTO_NONE:
		ND_PRINT("no next header");
		break;

	default:
		if (ndo->ndo_nflag==0 && (p_name = netdb_protoname(nh)) != NULL)
			ND_PRINT(" %s", p_name);
		else
			ND_PRINT(" ip-proto-%u", nh);
		ND_PRINT(" %u", length);
		break;
	}
}

/*
 * print an IP datagram.
 */
void
ip_print(netdissect_options *ndo,
	 const char *bp,
	 const int length)
{
	const struct ip *ip;
	int off;
	int hlen;
	int len;
	struct cksum_vec vec[1];
	uint8_t ip_tos, ip_ttl, ip_proto;
	uint16_t sum, ip_sum;
	const char *p_name;
	int truncated = 0;
	int presumed_tso = 0;

	ndo->ndo_protocol = "ip";
	ip = (const struct ip *)bp;

	if (!ndo->ndo_eflag) {
		nd_print_protocol_caps(ndo);
		ND_PRINT(" ");
	}

	ND_ICHECK_ZU(length, <, sizeof (struct ip));
	ND_ICHECKMSG_U("version", IP_V(ip), !=, 4);

	hlen = IP_HL(ip) * 4;
	ND_ICHECKMSG_ZU("header length", hlen, <, sizeof (struct ip));

	len = GET_BE_U_2(ip->ip_len);
	if (len > length) {
		ND_PRINT("[total length %u > length %u]", len, length);
		ND_PRINT(" ");
	}
	if (len == 0) {
		/* we guess that it is a TSO send */
		len = length;
		presumed_tso = 1;
	} else
		ND_ICHECKMSG_U("total length", len, <, hlen);

	ND_TCHECK_SIZE(ip);
	/*
	 * Cut off the snapshot length to the end of the IP payload.
	 */
	if (!nd_push_snaplen(ndo, bp, len)) {
		ND_PRINT("Can't push snaplen on buffer stack\n");
	}

	len -= hlen;

	off = GET_BE_U_2(ip->ip_off);

        ip_proto = GET_U_1(ip->ip_p);

        if (ndo->ndo_vflag) {
            ip_tos = GET_U_1(ip->ip_tos);
            ND_PRINT("(tos 0x%x", ip_tos);

            ip_ttl = GET_U_1(ip->ip_ttl);
            if (ip_ttl >= 1)
                ND_PRINT(", ttl %u", ip_ttl);

	    /*
	     * for the firewall guys, print id, offset.
             * On all but the last stick a "+" in the flags portion.
	     * For unfragmented datagrams, note the don't fragment flag.
	     */
	    ND_PRINT(", id %u, offset %u, flags [%s], proto %s (%u)",
                         GET_BE_U_2(ip->ip_id),
                         (off & IP_OFFMASK) * 8,
                         bittok2str(ip_frag_values, "none", off & (IP_RES|IP_DF|IP_MF)),
                         tok2str(ipproto_values, "unknown", ip_proto),
                         ip_proto);

	    ND_PRINT(")\n    ");
	    if (truncated) {
		ND_PRINT("%s > %s: ",
			 GET_IPADDR_STRING(ip->ip_src),
			 GET_IPADDR_STRING(ip->ip_dst));
		nd_pop_packet_info(ndo);
		return;
	    }
	}

	/*
	 * If this is fragment zero, hand it to the next higher
	 * level protocol.  Let them know whether there are more
	 * fragments.
	 */
	if ((off & IP_OFFMASK) == 0) {
		uint8_t nh = GET_U_1(ip->ip_p);

		if (nh != IPPROTO_TCP && nh != IPPROTO_UDP &&
		    nh != IPPROTO_SCTP && nh != IPPROTO_DCCP) {
			ND_PRINT("%s > %s: ",
				     GET_IPADDR_STRING(ip->ip_src),
				     GET_IPADDR_STRING(ip->ip_dst));
		}

		ip_demux_print(ndo, (const char *)ip + hlen, len, 4,
			       off & IP_MF, GET_U_1(ip->ip_ttl), nh, bp);
	} else {
		/*
		 * Ultra quiet now means that all this stuff should be
		 * suppressed.
		 */
		if (ndo->ndo_qflag > 1) {
			nd_pop_packet_info(ndo);
			return;
		}

		/*
		 * This isn't the first frag, so we're missing the
		 * next level protocol header.  print the ip addr
		 * and the protocol.
		 */
		ND_PRINT("%s > %s:", GET_IPADDR_STRING(ip->ip_src),
		          GET_IPADDR_STRING(ip->ip_dst));
		if (!ndo->ndo_nflag && (p_name = netdb_protoname(ip_proto)) != NULL)
			ND_PRINT(" %s", p_name);
		else
			ND_PRINT(" ip-proto-%u", ip_proto);
	}
	nd_pop_packet_info(ndo);
	return;

trunc:
	nd_print_trunc(ndo);
	return;

invalid:
	nd_print_invalid(ndo);
}