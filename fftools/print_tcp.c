#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "tcp.h"
#include "utils.h"

/* For source or destination ports tests (UDP, TCP, ...) */
#define IS_SRC_OR_DST_PORT(p) (sport == (p) || dport == (p))

#define ZEROLENOPT(o) ((o) == TCPOPT_EOL || (o) == TCPOPT_NOP)

const struct tok tcp_flag_values[] = {
        { TH_FIN, "F" },
        { TH_SYN, "S" },
        { TH_RST, "R" },
        { TH_PUSH, "P" },
        { TH_ACK, "." },
        { TH_URG, "U" },
        { TH_ECNECHO, "E" },
        { TH_CWR, "W" },
        { TH_AE, "e" },
        { 0, NULL }
};

struct tha {
        nd_ipv4 src;
        nd_ipv4 dst;
        int port;
};

struct tha6 {
        nd_ipv6 src;
        nd_ipv6 dst;
        int port;
};

struct tcp_seq_hash {
        struct tcp_seq_hash *nxt;
        struct tha addr;
        uint32_t seq;
        uint32_t ack;
};

struct tcp_seq_hash6 {
        struct tcp_seq_hash6 *nxt;
        struct tha6 addr;
        uint32_t seq;
        uint32_t ack;
};

struct cksum_vec {
	const uint8_t	*ptr;
	int		len;
};

static struct hnamemem tporttable[HASHNAMESIZE];

#define TSEQ_HASHSIZE 919

static struct tcp_seq_hash tcp_seq_hash4[TSEQ_HASHSIZE];
static struct tcp_seq_hash6 tcp_seq_hash6[TSEQ_HASHSIZE];

static const struct tok tcp_option_values[] = {
        { TCPOPT_EOL, "eol" },
        { TCPOPT_NOP, "nop" },
        { TCPOPT_MAXSEG, "mss" },
        { TCPOPT_WSCALE, "wscale" },
        { TCPOPT_SACKOK, "sackOK" },
        { TCPOPT_SACK, "sack" },
        { TCPOPT_ECHO, "echo" },
        { TCPOPT_ECHOREPLY, "echoreply" },
        { TCPOPT_TIMESTAMP, "TS" },
        { TCPOPT_CC, "cc" },
        { TCPOPT_CCNEW, "ccnew" },
        { TCPOPT_CCECHO, "ccecho" },
        { TCPOPT_SIGNATURE, "md5" },
        { TCPOPT_SCPS, "scps" },
        { TCPOPT_UTO, "uto" },
        { TCPOPT_TCPAO, "tcp-ao" },
        { TCPOPT_MPTCP, "mptcp" },
        { TCPOPT_FASTOPEN, "tfo" },
        { TCPOPT_EXPERIMENT2, "exp" },
        { 0, NULL }
};

struct h6namemem *
newh6namemem(netdissect_options *ndo)
{
	struct h6namemem *p;
	static struct h6namemem *ptr = NULL;
	static int num = 0;

	if (num  == 0) {
		num = 64;
		ptr = (struct h6namemem *)calloc(num, sizeof (*ptr));
	}
	--num;
	p = ptr++;
	return (p);
}

/*
 * Return a name for the IP6 address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
const char *
ip6addr_string(netdissect_options *ndo, const char *ap)
{
	struct hostent *hp;
	union {
		nd_ipv6 addr;
		struct for_hash_addr {
			char fill[14];
			uint16_t d;
		} addra;
	} addr;
	struct h6namemem *p;
	const char *cp;
	char ntop_buf[INET6_ADDRSTRLEN];

	memcpy(&addr, ap, sizeof(addr));
	p = &h6nametable[addr.addra.d & (HASHNAMESIZE-1)];
	for (; p->nxt; p = p->nxt) {
		if (memcmp(&p->addr, &addr, sizeof(addr)) == 0)
			return (p->name);
	}
	memcpy(p->addr, addr.addr, sizeof(nd_ipv6));
	p->nxt = newh6namemem(ndo);

	cp = addrtostr6(ap, ntop_buf, sizeof(ntop_buf));
	p->name = strdup(cp);

	return (p->name);
}

#define ADDCARRY(x)  {if ((x) > 65535) (x) -= 65535;}
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);}

uint16_t
in_cksum(const struct cksum_vec *vec, int veclen)
{
	const uint16_t *w;
	int sum = 0;
	int mlen = 0;
	int byte_swapped = 0;

	union {
		uint8_t		c[2];
		uint16_t	s;
	} s_util;
	union {
		uint16_t	s[2];
		uint32_t	l;
	} l_util;

	for (; veclen != 0; vec++, veclen--) {
		if (vec->len == 0)
			continue;
		w = (const uint16_t *)(const void *)vec->ptr;
		if (mlen == -1) {
			/*
			 * The first byte of this chunk is the continuation
			 * of a word spanning between this chunk and the
			 * last chunk.
			 *
			 * s_util.c[0] is already saved when scanning previous
			 * chunk.
			 */
			s_util.c[1] = *(const uint8_t *)w;
			sum += s_util.s;
			w = (const uint16_t *)(const void *)((const uint8_t *)w + 1);
			mlen = vec->len - 1;
		} else
			mlen = vec->len;
		/*
		 * Force to even boundary.
		 */
		if ((1 & (uintptr_t) w) && (mlen > 0)) {
			REDUCE;
			sum <<= 8;
			s_util.c[0] = *(const uint8_t *)w;
			w = (const uint16_t *)(const void *)((const uint8_t *)w + 1);
			mlen--;
			byte_swapped = 1;
		}
		/*
		 * Unroll the loop to make overhead from
		 * branches &c small.
		 */
		while ((mlen -= 32) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
			sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
			sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
			w += 16;
		}
		mlen += 32;
		while ((mlen -= 8) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			w += 4;
		}
		mlen += 8;
		if (mlen == 0 && byte_swapped == 0)
			continue;
		REDUCE;
		while ((mlen -= 2) >= 0) {
			sum += *w++;
		}
		if (byte_swapped) {
			REDUCE;
			sum <<= 8;
			byte_swapped = 0;
			if (mlen == -1) {
				s_util.c[1] = *(const uint8_t *)w;
				sum += s_util.s;
				mlen = 0;
			} else
				mlen = -1;
		} else if (mlen == -1)
			s_util.c[0] = *(const uint8_t *)w;
	}
	if (mlen == -1) {
		/* The last mbuf has odd # of bytes. Follow the
		   standard (the odd byte may be shifted left by 8 bits
		   or not as determined by endian-ness of the machine) */
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;
	return (~sum & 0xffff);
}

uint16_t
nextproto6_cksum(netdissect_options *ndo,
                 const struct ip6_hdr *ip6, const uint8_t *data,
		 int len, int covlen, uint8_t next_proto)
{
        struct {
                nd_ipv6 ph_src;
                nd_ipv6 ph_dst;
                uint32_t       ph_len;
                uint8_t        ph_zero[3];
                uint8_t        ph_nxt;
        } ph;
        struct cksum_vec vec[2];
        int nh;

        /* pseudo-header */
        memset(&ph, 0, sizeof(ph));
        GET_CPY_BYTES(&ph.ph_src, ip6->ip6_src, sizeof(nd_ipv6));
        nh = GET_U_1(ip6->ip6_nxt);

        ph.ph_len = htonl(len);
        ph.ph_nxt = next_proto;

        vec[0].ptr = (const uint8_t *)(void *)&ph;
        vec[0].len = sizeof(ph);
        vec[1].ptr = data;
        vec[1].len = covlen;

        return in_cksum(vec, 2);
}

static uint16_t
tcp6_cksum(netdissect_options *ndo,
           const struct ip6_hdr *ip6,
           const struct tcphdr *tp,
           int len)
{
        return nextproto6_cksum(ndo, ip6, (const uint8_t *)tp, len, len,
                                IPPROTO_TCP);
}

static inline uint32_t
EXTRACT_IPV4_TO_NETWORK_ORDER(const void *p)
{
	uint32_t addr;

	UNALIGNED_MEMCPY(&addr, p, sizeof(uint32_t));
	return addr;
}

static inline uint32_t
get_ipv4_to_network_order(netdissect_options *ndo, const char *p)
{
	return EXTRACT_IPV4_TO_NETWORK_ORDER(p);
}

#define GET_IPV4_TO_NETWORK_ORDER(p) get_ipv4_to_network_order(ndo, (const u_char *)(p))

const char *
tcpport_string(netdissect_options *ndo, short port)
{
	struct hnamemem *tp;
	uint32_t i = port;
	char buf[sizeof("00000")];

	for (tp = &tporttable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
		if (tp->addr == i)
			return (tp->name);

	tp->addr = i;
	tp->nxt = newhnamemem(ndo);

	(void)snprintf(buf, sizeof(buf), "%u", i);
	tp->name = strdup(buf);

	return (tp->name);
}

#define GET_IPV4_TO_NETWORK_ORDER(p) get_ipv4_to_network_order(ndo, (const char *)(p))

static uint32_t
ip_finddst(netdissect_options *ndo,
           const struct ip *ip)
{
	int length;
	int len;
	const char *cp;

	cp = (const char *)(ip + 1);
	length = IP_HL(ip) * 4;
	if (length < sizeof(struct ip))
		goto trunc;
	length -= sizeof(struct ip);

	for (; length != 0; cp += len, length -= len) {
		int tt;

		tt = GET_U_1(cp);
		if (tt == IPOPT_EOL)
			break;
		else if (tt == IPOPT_NOP)
			len = 1;
		else {
			len = GET_U_1(cp + 1);
			if (len < 2)
				break;
		}
		if (length < len)
			goto trunc;
		ND_TCHECK_LEN(cp, len);
		switch (tt) {

		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (len < 7)
				break;
			return (GET_IPV4_TO_NETWORK_ORDER(cp + len - 4));
		}
	}
trunc:
	return (GET_IPV4_TO_NETWORK_ORDER(ip->ip_dst));
}

uint16_t
nextproto4_cksum(netdissect_options *ndo,
                 const struct ip *ip, const uint8_t *data,
                 int len, int covlen, uint8_t next_proto)
{
	struct phdr {
		uint32_t src;
		uint32_t dst;
		uint8_t mbz;
		uint8_t proto;
		uint16_t len;
	} ph;
	struct cksum_vec vec[2];

	/* pseudo-header.. */
	ph.len = htons((uint16_t)len);
	ph.mbz = 0;
	ph.proto = next_proto;
	ph.src = GET_IPV4_TO_NETWORK_ORDER(ip->ip_src);
	if (IP_HL(ip) == 5)
		ph.dst = GET_IPV4_TO_NETWORK_ORDER(ip->ip_dst);
	else
		ph.dst = ip_finddst(ndo, ip);

	vec[0].ptr = (const uint8_t *)(void *)&ph;
	vec[0].len = sizeof(ph);
	vec[1].ptr = data;
	vec[1].len = covlen;
	return (in_cksum(vec, 2));
}

static uint16_t
tcp_cksum(netdissect_options *ndo,
          const struct ip *ip,
          const struct tcphdr *tp,
          int len)
{
        return nextproto4_cksum(ndo, ip, (const uint8_t *)tp, len, len,
                                IPPROTO_TCP);
}

uint16_t
in_cksum_shouldbe(uint16_t sum, uint16_t computed_sum)
{
	uint32_t shouldbe;

	shouldbe = sum;
	shouldbe += ntohs(computed_sum);
	shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);
	shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);
	return (uint16_t)shouldbe;
}

void
tcp_print(netdissect_options *ndo,
          const char *bp, int length,
          const char *bp2, int fragmented)
{
        const struct tcphdr *tp;
        const struct ip *ip;
        uint16_t flags;
        int hlen;
        char ch;
        uint16_t sport, dport, win, urp;
        uint32_t seq, ack, thseq, thack;
        int utoval;
        uint16_t magic;
        int rev;
        const struct ip6_hdr *ip6;
        int header_len;	/* Header length in bytes */

        ndo->ndo_protocol = "tcp";
        tp = (const struct tcphdr *)bp;
        ip = (const struct ip *)bp2;
        if (IP_V(ip) == 6)
                ip6 = (const struct ip6_hdr *)bp2;
        else
                ip6 = NULL;
        ch = '\0';
        if (!ND_TTEST_2(tp->th_dport)) {
                if (ip6) {
                        ND_PRINT("%s > %s:",
                                 GET_IP6ADDR_STRING(ip6->ip6_src),
                                 GET_IP6ADDR_STRING(ip6->ip6_dst));
                } else {
                        ND_PRINT("%s > %s:",
                                 GET_IPADDR_STRING(ip->ip_src),
                                 GET_IPADDR_STRING(ip->ip_dst));
                }
                nd_trunc_longjmp(ndo);
        }

        sport = GET_BE_U_2(tp->th_sport);
        dport = GET_BE_U_2(tp->th_dport);

        if (ip6) {
                if (GET_U_1(ip6->ip6_nxt) == IPPROTO_TCP) {
                        ND_PRINT("%s.%s > %s.%s: ",
                                 GET_IP6ADDR_STRING(ip6->ip6_src),
                                 tcpport_string(ndo, sport),
                                 GET_IP6ADDR_STRING(ip6->ip6_dst),
                                 tcpport_string(ndo, dport));
                } else {
                        ND_PRINT("%s > %s: ",
                                 tcpport_string(ndo, sport), tcpport_string(ndo, dport));
                }
        } else {
                if (GET_U_1(ip->ip_p) == IPPROTO_TCP) {
                        ND_PRINT("%s.%s > %s.%s: ",
                                 GET_IPADDR_STRING(ip->ip_src),
                                 tcpport_string(ndo, sport),
                                 GET_IPADDR_STRING(ip->ip_dst),
                                 tcpport_string(ndo, dport));
                } else {
                        ND_PRINT("%s > %s: ",
                                 tcpport_string(ndo, sport), tcpport_string(ndo, dport));
                }
        }

        hlen = TH_OFF(tp) * 4;

        if (hlen < sizeof(*tp)) {
                ND_PRINT(" tcp %u [bad hdr length %u - too short, < %zu]",
                         length - hlen, hlen, sizeof(*tp));
                goto invalid;
        }

        seq = GET_BE_U_4(tp->th_seq);
        ack = GET_BE_U_4(tp->th_ack);
        win = GET_BE_U_2(tp->th_win);
        urp = GET_BE_U_2(tp->th_urp);

        if (ndo->ndo_qflag) {
                ND_PRINT("tcp %u", length - hlen);
                if (hlen > length) {
                        ND_PRINT(" [bad hdr length %u - too long, > %u]",
                                 hlen, length);
                        goto invalid;
                }
                return;
        }

        flags = tcp_get_flags(tp);
        ND_PRINT("Flags [%s]", bittok2str_nosep(tcp_flag_values, "none", flags));

        if (!ndo->ndo_Sflag && (flags & TH_ACK)) {
                /*
                 * Find (or record) the initial sequence numbers for
                 * this conversation.  (we pick an arbitrary
                 * collating order so there's only one entry for
                 * both directions).
                 */
                rev = 0;
                if (ip6) {
                        struct tcp_seq_hash6 *th;
                        struct tcp_seq_hash6 *tcp_seq_hash;
                        const void *src, *dst;
                        struct tha6 tha;

                        tcp_seq_hash = tcp_seq_hash6;
                        src = (const void *)ip6->ip6_src;
                        dst = (const void *)ip6->ip6_dst;
                        if (sport > dport)
                                rev = 1;
                        else if (sport == dport) {
                                if (UNALIGNED_MEMCMP(src, dst, sizeof(ip6->ip6_dst)) > 0)
                                        rev = 1;
                        }
                        if (rev) {
                                UNALIGNED_MEMCPY(&tha.src, dst, sizeof(ip6->ip6_dst));
                                UNALIGNED_MEMCPY(&tha.dst, src, sizeof(ip6->ip6_src));
                                tha.port = ((int)dport) << 16 | sport;
                        } else {
                                UNALIGNED_MEMCPY(&tha.dst, dst, sizeof(ip6->ip6_dst));
                                UNALIGNED_MEMCPY(&tha.src, src, sizeof(ip6->ip6_src));
                                tha.port = ((int)sport) << 16 | dport;
                        }

                        for (th = &tcp_seq_hash[tha.port % TSEQ_HASHSIZE];
                             th->nxt; th = th->nxt)
                                if (memcmp((char *)&tha, (char *)&th->addr,
                                           sizeof(th->addr)) == 0)
                                        break;

                        if (!th->nxt || (flags & TH_SYN)) {
                                /* didn't find it or new conversation */
                                /* calloc() return used by the 'tcp_seq_hash6'
                                   hash table: do not free() */
                                if (th->nxt == NULL) {
                                        th->nxt = (struct tcp_seq_hash6 *)
                                                calloc(1, sizeof(*th));
                                }
                                th->addr = tha;
                                if (rev)
                                        th->ack = seq, th->seq = ack - 1;
                                else
                                        th->seq = seq, th->ack = ack - 1;
                        } else {
                                if (rev)
                                        seq -= th->ack, ack -= th->seq;
                                else
                                        seq -= th->seq, ack -= th->ack;
                        }

                        thseq = th->seq;
                        thack = th->ack;
                } else {
                        struct tcp_seq_hash *th;
                        struct tcp_seq_hash *tcp_seq_hash;
                        struct tha tha;

                        tcp_seq_hash = tcp_seq_hash4;
                        if (sport > dport)
                                rev = 1;
                        else if (sport == dport) {
                                if (UNALIGNED_MEMCMP(ip->ip_src, ip->ip_dst, sizeof(ip->ip_dst)) > 0)
                                        rev = 1;
                        }
                        if (rev) {
                                UNALIGNED_MEMCPY(&tha.src, ip->ip_dst,
                                                 sizeof(ip->ip_dst));
                                UNALIGNED_MEMCPY(&tha.dst, ip->ip_src,
                                                 sizeof(ip->ip_src));
                                tha.port = ((int)dport) << 16 | sport;
                        } else {
                                UNALIGNED_MEMCPY(&tha.dst, ip->ip_dst,
                                                 sizeof(ip->ip_dst));
                                UNALIGNED_MEMCPY(&tha.src, ip->ip_src,
                                                 sizeof(ip->ip_src));
                                tha.port = ((int)sport) << 16 | dport;
                        }

                        for (th = &tcp_seq_hash[tha.port % TSEQ_HASHSIZE];
                             th->nxt; th = th->nxt)
                                if (memcmp((char *)&tha, (char *)&th->addr,
                                           sizeof(th->addr)) == 0)
                                        break;

                        if (!th->nxt || (flags & TH_SYN)) {
                                /* didn't find it or new conversation */
                                /* calloc() return used by the 'tcp_seq_hash4'
                                   hash table: do not free() */
                                if (th->nxt == NULL) {
                                        th->nxt = (struct tcp_seq_hash *)
                                                calloc(1, sizeof(*th));
                                }
                                th->addr = tha;
                                if (rev)
                                        th->ack = seq, th->seq = ack - 1;
                                else
                                        th->seq = seq, th->ack = ack - 1;
                        } else {
                                if (rev)
                                        seq -= th->ack, ack -= th->seq;
                                else
                                        seq -= th->seq, ack -= th->ack;
                        }

                        thseq = th->seq;
                        thack = th->ack;
                }
        } else {
                /*fool gcc*/
                thseq = thack = rev = 0;
        }
        if (hlen > length) {
                ND_PRINT(" [bad hdr length %u - too long, > %u]",
                         hlen, length);
                goto invalid;
        }

        if (ndo->ndo_vflag && !ndo->ndo_Kflag && !fragmented) {
                /* Check the checksum, if possible. */
                uint16_t sum, tcp_sum;

                if (IP_V(ip) == 4) {
                        if (ND_TTEST_LEN(tp->th_sport, length)) {
                                sum = tcp_cksum(ndo, ip, tp, length);
                                tcp_sum = GET_BE_U_2(tp->th_sum);

                                ND_PRINT(", cksum 0x%04x", tcp_sum);
                                if (sum != 0)
                                        ND_PRINT(" (incorrect -> 0x%04x)",
                                            in_cksum_shouldbe(tcp_sum, sum));
                                else
                                        ND_PRINT(" (correct)");
                        }
                } else if (IP_V(ip) == 6) {
                        if (ND_TTEST_LEN(tp->th_sport, length)) {
                                sum = tcp6_cksum(ndo, ip6, tp, length);
                                tcp_sum = GET_BE_U_2(tp->th_sum);

                                ND_PRINT(", cksum 0x%04x", tcp_sum);
                                if (sum != 0)
                                        ND_PRINT(" (incorrect -> 0x%04x)",
                                            in_cksum_shouldbe(tcp_sum, sum));
                                else
                                        ND_PRINT(" (correct)");

                        }
                }
        }

        length -= hlen;
        if (ndo->ndo_vflag > 1 || length > 0 || flags & (TH_SYN | TH_FIN | TH_RST)) {
                ND_PRINT(", seq %u", seq);

                if (length > 0) {
                        ND_PRINT(":%u", seq + length);
                }
        }

        if (flags & TH_ACK) {
                ND_PRINT(", ack %u", ack);
        }

        ND_PRINT(", win %u", win);

        if (flags & TH_URG)
                ND_PRINT(", urg %u", urp);
        /*
         * Handle any options.
         */
        if (hlen > sizeof(*tp)) {
                const char *cp;
                int i, opt, datalen;
                int len;

                hlen -= sizeof(*tp);
                cp = (const char *)tp + sizeof(*tp);
                ND_PRINT(", options [");
                while (hlen != 0) {
                        if (ch != '\0')
                                ND_PRINT("%c", ch);
                        opt = GET_U_1(cp);
                        cp++;
                        if (ZEROLENOPT(opt))
                                len = 1;
                        else {
                                len = GET_U_1(cp);
                                cp++;	/* total including type, len */
                                if (len < 2 || len > hlen)
                                        goto bad;
                                --hlen;		/* account for length byte */
                        }
                        --hlen;			/* account for type byte */
                        datalen = 0;

/* Bail if "l" bytes of data are not left or were not captured  */
#define LENCHECK(l) { if ((l) > hlen) goto bad; }

                        ND_PRINT("%s", tok2str(tcp_option_values, "unknown-%u", opt));

                        switch (opt) {

                        case TCPOPT_MAXSEG:
                                datalen = 2;
                                LENCHECK(datalen);
                                ND_PRINT(" %u", GET_BE_U_2(cp));
                                break;

                        case TCPOPT_WSCALE:
                                datalen = 1;
                                LENCHECK(datalen);
                                ND_PRINT(" %u", GET_U_1(cp));
                                break;

                        case TCPOPT_SACK:
                                datalen = len - 2;
                                if (datalen % 8 != 0) {
                                        ND_PRINT(" invalid sack");
                                } else {
                                        uint32_t s, e;

                                        ND_PRINT(" %u ", datalen / 8);
                                        for (i = 0; i < datalen; i += 8) {
                                                LENCHECK(i + 4);
                                                s = GET_BE_U_4(cp + i);
                                                LENCHECK(i + 8);
                                                e = GET_BE_U_4(cp + i + 4);
                                                if (rev) {
                                                        s -= thseq;
                                                        e -= thseq;
                                                } else {
                                                        s -= thack;
                                                        e -= thack;
                                                }
                                                ND_PRINT("{%u:%u}", s, e);
                                        }
                                }
                                break;

                        case TCPOPT_CC:
                        case TCPOPT_CCNEW:
                        case TCPOPT_CCECHO:
                        case TCPOPT_ECHO:
                        case TCPOPT_ECHOREPLY:

                                /*
                                 * those options share their semantics.
                                 * fall through
                                 */
                                datalen = 4;
                                LENCHECK(datalen);
                                ND_PRINT(" %u", GET_BE_U_4(cp));
                                break;

                        case TCPOPT_TIMESTAMP:
                                datalen = 8;
                                LENCHECK(datalen);
                                ND_PRINT(" val %u ecr %u",
                                             GET_BE_U_4(cp),
                                             GET_BE_U_4(cp + 4));
                                break;

                        case TCPOPT_SCPS:
                                datalen = 2;
                                LENCHECK(datalen);
                                ND_PRINT(" cap %02x id %u", GET_U_1(cp),
                                         GET_U_1(cp + 1));
                                break;

                        case TCPOPT_TCPAO:
                                datalen = len - 2;
                                /* RFC 5925 Section 2.2:
                                 * "The Length value MUST be greater than or equal to 4."
                                 * (This includes the Kind and Length fields already processed
                                 * at this point.)
                                 */
                                if (datalen < 2) {
                                        ND_PRINT("invalid");
                                } else {
                                        LENCHECK(1);
                                        ND_PRINT(" keyid %u", GET_U_1(cp));
                                        LENCHECK(2);
                                        ND_PRINT(" rnextkeyid %u",
                                                 GET_U_1(cp + 1));
                                        if (datalen > 2) {
                                                ND_PRINT(" mac 0x");
                                                for (i = 2; i < datalen; i++) {
                                                        LENCHECK(i + 1);
                                                        ND_PRINT("%02x",
                                                                 GET_U_1(cp + i));
                                                }
                                        }
                                }
                                break;

                        case TCPOPT_EOL:
                        case TCPOPT_NOP:
                        case TCPOPT_SACKOK:
                                /*
                                 * Nothing interesting.
                                 * fall through
                                 */
                                break;

                        case TCPOPT_UTO:
                                datalen = 2;
                                LENCHECK(datalen);
                                utoval = GET_BE_U_2(cp);
                                ND_PRINT(" 0x%x", utoval);
                                if (utoval & 0x0001)
                                        utoval = (utoval >> 1) * 60;
                                else
                                        utoval >>= 1;
                                ND_PRINT(" %u", utoval);
                                break;

                        default:
                                datalen = len - 2;
                                if (datalen)
                                        ND_PRINT(" 0x");
                                for (i = 0; i < datalen; ++i) {
                                        LENCHECK(i + 1);
                                        ND_PRINT("%02x", GET_U_1(cp + i));
                                }
                                break;
                        }

                        /* Account for data printed */
                        cp += datalen;
                        hlen -= datalen;

                        /* Check specification against observed length */
                        ++datalen;		/* option octet */
                        if (!ZEROLENOPT(opt))
                                ++datalen;	/* size octet */
                        if (datalen != len)
                                ND_PRINT("[len %u]", len);
                        ch = ',';
                        if (opt == TCPOPT_EOL)
                                break;
                }
                ND_PRINT("]");
        }

        /*
         * Print length field before crawling down the stack.
         */
        ND_PRINT(", length %u", length);

        if (length == 0)
                return;

        /*
         * Decode payload if necessary.
         */
        header_len = TH_OFF(tp) * 4;
        /*
         * Do a bounds check before decoding the payload.
         * At least the header data is required.
         */
        if (!ND_TTEST_LEN(bp, header_len)) {
                ND_PRINT(" [remaining caplen(%u) < header length(%u)]",
                         ND_BYTES_AVAILABLE_AFTER(bp), header_len);
                nd_trunc_longjmp(ndo);
        }
        bp += header_len;

        if (IS_SRC_OR_DST_PORT(HTTP_PORT)) {
                ND_PRINT(": ");
                // http_print(ndo, bp, length);
        } 

        ND_PRINT("\n\n");

        return;
bad:
        ND_PRINT("[bad opt]");
        if (ch != '\0')
                ND_PRINT("]");
        return;
invalid:
        ND_PRINT("invalid");
}