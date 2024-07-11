#include <string.h>
#include <stdint.h>

#include "utils.h"

#define TOKBUFSIZE 128

static const char *netdb_protocol_names[256] = {
	"hopopt",		   /* 0 (IPPROTO_HOPOPTS, IPv6 Hop-by-Hop Option) */
	"icmp",			   /* 1 (IPPROTO_ICMP, Internet Control Message) */
	"igmp",			   /* 2 (IPPROTO_IGMP, Internet Group Management) */
	"ggp",			   /* 3 (Gateway-to-Gateway) */
	"ipencap",		   /* 4 (IPPROTO_IPV4, IPv4 encapsulation) */
	"st",			   /* 5 (Stream, ST datagram mode) */
	"tcp",			   /* 6 (IPPROTO_TCP, Transmission Control) */
	"cbt",			   /* 7 (CBT) */
	"egp",			   /* 8 (IPPROTO_EGP, Exterior Gateway Protocol) */
	"igp",			   /* 9 (IPPROTO_PIGP, "any private interior gateway
						*   (used by Cisco for their IGRP)")
						*/
	"bbn-rcc-mon",	   /* 10 (BBN RCC Monitoring) */
	"nvp-ii",		   /* 11 (Network Voice Protocol) */
	"pup",			   /* 12 (PARC universal packet protocol) */
	"argus",		   /* 13 (ARGUS) */
	"emcon",		   /* 14 (EMCON) */
	"xnet",			   /* 15 (Cross Net Debugger) */
	"chaos",		   /* 16 (Chaos) */
	"udp",			   /* 17 (IPPROTO_UDP, User Datagram) */
	"mux",			   /* 18 (Multiplexing) */
	"dcn-meas",		   /* 19 (DCN Measurement Subsystems) */
	"hmp",			   /* 20 (Host Monitoring) */
	"prm",			   /* 21 (Packet Radio Measurement) */
	"xns-idp",		   /* 22 (XEROX NS IDP) */
	"trunk-1",		   /* 23 (Trunk-1) */
	"trunk-2",		   /* 24 (Trunk-2) */
	"leaf-1",		   /* 25 (Leaf-1) */
	"leaf-2",		   /* 26 (Leaf-2) */
	"rdp",			   /* 27 (Reliable Data Protocol) */
	"irtp",			   /* 28 (Internet Reliable Transaction) */
	"iso-tp4",		   /* 29 (ISO Transport Protocol Class 4) */
	"netblt",		   /* 30 (Bulk Data Transfer Protocol) */
	"mfe-nsp",		   /* 31 (MFE Network Services Protocol) */
	"merit-inp",	   /* 32 (MERIT Internodal Protocol) */
	"dccp",			   /* 33 (IPPROTO_DCCP, Datagram Congestion
						*    Control Protocol)
						*/
	"3pc",			   /* 34 (Third Party Connect Protocol) */
	"idpr",			   /* 35 (Inter-Domain Policy Routing Protocol) */
	"xtp",			   /* 36 (Xpress Transfer Protocol) */
	"ddp",			   /* 37 (Datagram Delivery Protocol) */
	"idpr-cmtp",	   /* 38 (IDPR Control Message Transport Proto) */
	"tp++",			   /* 39 (TP++ Transport Protocol) */
	"il",			   /* 40 (IL Transport Protocol) */
	"ipv6",			   /* 41 (IPPROTO_IPV6, IPv6 encapsulation) */
	"sdrp",			   /* 42 (Source Demand Routing Protocol) */
	"ipv6-route",	   /* 43 (IPPROTO_ROUTING, Routing Header for IPv6) */
	"ipv6-frag",	   /* 44 (IPPROTO_FRAGMENT, Fragment Header for
						*    IPv6)
						*/
	"idrp",			   /* 45 (Inter-Domain Routing Protocol) */
	"rsvp",			   /* 46 (IPPROTO_RSVP, Reservation Protocol) */
	"gre",			   /* 47 (IPPROTO_GRE, Generic Routing
						*    Encapsulation)
						*/
	"dsr",			   /* 48 (Dynamic Source Routing Protocol) */
	"bna",			   /* 49 (BNA) */
	"esp",			   /* 50 (IPPROTO_ESP, Encap Security Payload) */
	"ah",			   /* 51 (IPPROTO_AH, Authentication Header) */
	"i-nlsp",		   /* 52 (Integrated Net Layer Security TUBA) */
	"swipe",		   /* 53 (IP with Encryption) */
	"narp",			   /* 54 (NBMA Address Resolution Protocol) */
	"mobile",		   /* 55 (IPPROTO_MOBILE, IP Mobility) */
	"tlsp",			   /* 56 (Transport Layer Security Protocol using
						*    Kryptonet key management)
						*/
	"skip",			   /* 57 (SKIP) */
	"ipv6-icmp",	   /* 58 (IPPROTO_ICMPV6, ICMP for IPv6) */
	"ipv6-nonxt",	   /* 59 (IPPROTO_NONE, No Next Header for IPv6) */
	"ipv6-opts",	   /* 60 (IPPROTO_DSTOPTS, Destination Options for
						*    IPv6)
						*/
	NULL,			   /* 61 (any host internal protocol) */
	"cftp",			   /* 62 (IPPROTO_MOBILITY_OLD, CFTP, see the note
						*    in ipproto.h)
						*/
	NULL,			   /* 63 (any local network) */
	"sat-expak",	   /* 64 (SATNET and Backroom EXPAK) */
	"kryptolan",	   /* 65 (Kryptolan) */
	"rvd",			   /* 66 (MIT Remote Virtual Disk Protocol) */
	"ippc",			   /* 67 (Internet Pluribus Packet Core) */
	NULL,			   /* 68 (any distributed file system) */
	"sat-mon",		   /* 69 (SATNET Monitoring) */
	"visa",			   /* 70 (VISA Protocol) */
	"ipcv",			   /* 71 (Internet Packet Core Utility) */
	"cpnx",			   /* 72 (Computer Protocol Network Executive) */
	"rspf",			   /* 73 (Radio Shortest Path First, CPHB -- Computer
						*    Protocol Heart Beat -- in IANA)
						*/
	"wsn",			   /* 74 (Wang Span Network) */
	"pvp",			   /* 75 (Packet Video Protocol) */
	"br-sat-mon",	   /* 76 (Backroom SATNET Monitoring) */
	"sun-nd",		   /* 77 (IPPROTO_ND, SUN ND PROTOCOL-Temporary) */
	"wb-mon",		   /* 78 (WIDEBAND Monitoring) */
	"wb-expak",		   /* 79 (WIDEBAND EXPAK) */
	"iso-ip",		   /* 80 (ISO Internet Protocol) */
	"vmtp",			   /* 81 (Versatile Message Transport) */
	"secure-vmtp",	   /* 82 (Secure VMTP) */
	"vines",		   /* 83 (VINES) */
	"ttp",			   /* 84 (Transaction Transport Protocol, also IPTM --
						*    Internet Protocol Traffic Manager)
						*/
	"nsfnet-igp",	   /* 85 (NSFNET-IGP) */
	"dgp",			   /* 86 (Dissimilar Gateway Protocol) */
	"tcf",			   /* 87 (TCF) */
	"eigrp",		   /* 88 (IPPROTO_EIGRP, Cisco EIGRP) */
	"ospf",			   /* 89 (IPPROTO_OSPF, Open Shortest Path First
						*    IGP)
						*/
	"sprite-rpc",	   /* 90 (Sprite RPC Protocol) */
	"larp",			   /* 91 (Locus Address Resolution Protocol) */
	"mtp",			   /* 92 (Multicast Transport Protocol) */
	"ax.25",		   /* 93 (AX.25 Frames) */
	"ipip",			   /* 94 (IP-within-IP Encapsulation Protocol) */
	"micp",			   /* 95 (Mobile Internetworking Control Pro.) */
	"scc-sp",		   /* 96 (Semaphore Communications Sec. Pro.) */
	"etherip",		   /* 97 (Ethernet-within-IP Encapsulation) */
	"encap",		   /* 98 (Encapsulation Header) */
	NULL,			   /* 99 (any private encryption scheme) */
	"gmtp",			   /* 100 (GMTP) */
	"ifmp",			   /* 101 (Ipsilon Flow Management Protocol) */
	"pnni",			   /* 102 (PNNI over IP) */
	"pim",			   /* 103 (IPPROTO_PIM, Protocol Independent
						*     Multicast)
						*/
	"aris",			   /* 104 (ARIS) */
	"scps",			   /* 105 (SCPS) */
	"qnx",			   /* 106 (QNX) */
	"a/n",			   /* 107 (Active Networks) */
	"ipcomp",		   /* 108 (IPPROTO_IPCOMP, IP Payload Compression
						*     Protocol)
						*/
	"snp",			   /* 109 (Sitara Networks Protocol) */
	"compaq-peer",	   /* 110 (Compaq Peer Protocol) */
	"ipx-in-ip",	   /* 111 (IPX in IP) */
	"vrrp",			   /* 112 (IPPROTO_VRRP, Virtual Router Redundancy
						*     Protocol)
						*/
	"pgm",			   /* 113 (IPPROTO_PGM, PGM Reliable Transport
						*     Protocol)
						*/
	NULL,			   /* 114 (any 0-hop protocol) */
	"l2tp",			   /* 115 (Layer Two Tunneling Protocol) */
	"ddx",			   /* 116 (D-II Data Exchange (DDX)) */
	"iatp",			   /* 117 (Interactive Agent Transfer Protocol) */
	"stp",			   /* 118 (Schedule Transfer Protocol) */
	"srp",			   /* 119 (SpectraLink Radio Protocol) */
	"uti",			   /* 120 (UTI) */
	"smp",			   /* 121 (Simple Message Protocol) */
	"sm",			   /* 122 (Simple Multicast Protocol) */
	"ptp",			   /* 123 (Performance Transparency Protocol) */
	"isis",			   /* 124 (ISIS over IPv4) */
	"fire",			   /* 125 (FIRE) */
	"crtp",			   /* 126 (Combat Radio Transport Protocol) */
	"crudp",		   /* 127 (Combat Radio User Datagram) */
	"sscopmce",		   /* 128 (SSCOPMCE) */
	"iplt",			   /* 129 (IPLT) */
	"sps",			   /* 130 (Secure Packet Shield) */
	"pipe",			   /* 131 (Private IP Encapsulation within IP) */
	"sctp",			   /* 132 (IPPROTO_SCTP, Stream Control Transmission
						*     Protocol)
						*/
	"fc",			   /* 133 (Fibre Channel) */
	"rsvp-e2e-ignore", /* 134 (RSVP-E2E-IGNORE) */
	"mobility-header", /* 135 (IPPROTO_MOBILITY, Mobility Header) */
	"udplite",		   /* 136 (UDPLite) */
	"mpls-in-ip",	   /* 137 (MPLS-in-IP) */
	"manet",		   /* 138 (MANET Protocols) */
	"hip",			   /* 139 (Host Identity Protocol) */
	"shim6",		   /* 140 (Shim6 Protocol) */
	"wesp",			   /* 141 (Wrapped Encapsulating Security Payload) */
	"rohc",			   /* 142 (Robust Header Compression) */
	NULL,			   /* 143 (unassigned) */
	NULL,			   /* 144 (unassigned) */
	NULL,			   /* 145 (unassigned) */
	NULL,			   /* 146 (unassigned) */
	NULL,			   /* 147 (unassigned) */
	NULL,			   /* 148 (unassigned) */
	NULL,			   /* 149 (unassigned) */
	NULL,			   /* 150 (unassigned) */
	NULL,			   /* 151 (unassigned) */
	NULL,			   /* 152 (unassigned) */
	NULL,			   /* 153 (unassigned) */
	NULL,			   /* 154 (unassigned) */
	NULL,			   /* 155 (unassigned) */
	NULL,			   /* 156 (unassigned) */
	NULL,			   /* 157 (unassigned) */
	NULL,			   /* 158 (unassigned) */
	NULL,			   /* 159 (unassigned) */
	NULL,			   /* 160 (unassigned) */
	NULL,			   /* 161 (unassigned) */
	NULL,			   /* 162 (unassigned) */
	NULL,			   /* 163 (unassigned) */
	NULL,			   /* 164 (unassigned) */
	NULL,			   /* 165 (unassigned) */
	NULL,			   /* 166 (unassigned) */
	NULL,			   /* 167 (unassigned) */
	NULL,			   /* 168 (unassigned) */
	NULL,			   /* 169 (unassigned) */
	NULL,			   /* 170 (unassigned) */
	NULL,			   /* 171 (unassigned) */
	NULL,			   /* 172 (unassigned) */
	NULL,			   /* 173 (unassigned) */
	NULL,			   /* 174 (unassigned) */
	NULL,			   /* 175 (unassigned) */
	NULL,			   /* 176 (unassigned) */
	NULL,			   /* 177 (unassigned) */
	NULL,			   /* 178 (unassigned) */
	NULL,			   /* 179 (unassigned) */
	NULL,			   /* 180 (unassigned) */
	NULL,			   /* 181 (unassigned) */
	NULL,			   /* 182 (unassigned) */
	NULL,			   /* 183 (unassigned) */
	NULL,			   /* 184 (unassigned) */
	NULL,			   /* 185 (unassigned) */
	NULL,			   /* 186 (unassigned) */
	NULL,			   /* 187 (unassigned) */
	NULL,			   /* 188 (unassigned) */
	NULL,			   /* 189 (unassigned) */
	NULL,			   /* 190 (unassigned) */
	NULL,			   /* 191 (unassigned) */
	NULL,			   /* 192 (unassigned) */
	NULL,			   /* 193 (unassigned) */
	NULL,			   /* 194 (unassigned) */
	NULL,			   /* 195 (unassigned) */
	NULL,			   /* 196 (unassigned) */
	NULL,			   /* 197 (unassigned) */
	NULL,			   /* 198 (unassigned) */
	NULL,			   /* 199 (unassigned) */
	NULL,			   /* 200 (unassigned) */
	NULL,			   /* 201 (unassigned) */
	NULL,			   /* 202 (unassigned) */
	NULL,			   /* 203 (unassigned) */
	NULL,			   /* 204 (unassigned) */
	NULL,			   /* 205 (unassigned) */
	NULL,			   /* 206 (unassigned) */
	NULL,			   /* 207 (unassigned) */
	NULL,			   /* 208 (unassigned) */
	NULL,			   /* 209 (unassigned) */
	NULL,			   /* 210 (unassigned) */
	NULL,			   /* 211 (unassigned) */
	NULL,			   /* 212 (unassigned) */
	NULL,			   /* 213 (unassigned) */
	NULL,			   /* 214 (unassigned) */
	NULL,			   /* 215 (unassigned) */
	NULL,			   /* 216 (unassigned) */
	NULL,			   /* 217 (unassigned) */
	NULL,			   /* 218 (unassigned) */
	NULL,			   /* 219 (unassigned) */
	NULL,			   /* 220 (unassigned) */
	NULL,			   /* 221 (unassigned) */
	NULL,			   /* 222 (unassigned) */
	NULL,			   /* 223 (unassigned) */
	NULL,			   /* 224 (unassigned) */
	NULL,			   /* 225 (unassigned) */
	NULL,			   /* 226 (unassigned) */
	NULL,			   /* 227 (unassigned) */
	NULL,			   /* 228 (unassigned) */
	NULL,			   /* 229 (unassigned) */
	NULL,			   /* 230 (unassigned) */
	NULL,			   /* 231 (unassigned) */
	NULL,			   /* 232 (unassigned) */
	NULL,			   /* 233 (unassigned) */
	NULL,			   /* 234 (unassigned) */
	NULL,			   /* 235 (unassigned) */
	NULL,			   /* 236 (unassigned) */
	NULL,			   /* 237 (unassigned) */
	NULL,			   /* 238 (unassigned) */
	NULL,			   /* 239 (unassigned) */
	NULL,			   /* 240 (unassigned) */
	NULL,			   /* 241 (unassigned) */
	NULL,			   /* 242 (unassigned) */
	NULL,			   /* 243 (unassigned) */
	NULL,			   /* 244 (unassigned) */
	NULL,			   /* 245 (unassigned) */
	NULL,			   /* 246 (unassigned) */
	NULL,			   /* 247 (unassigned) */
	NULL,			   /* 248 (unassigned) */
	NULL,			   /* 249 (unassigned) */
	NULL,			   /* 250 (unassigned) */
	NULL,			   /* 251 (unassigned) */
	NULL,			   /* 252 (unassigned) */
	"exptest-253",	   /* 253 (Use for experimentation and testing,
						*     RFC 3692)
						*/
	"exptest-254",	   /* 254 (Use for experimentation and testing,
						*     RFC 3692)
						*/
	"reserved",		   /* 255 (reserved) */
};

size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0)
	{
		do
		{
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0)
	{
		if (siz != 0)
			*d = '\0'; /* NUL-terminate dst */
		while (*s++)
			;
	}

	return (s - src - 1); /* count does not include NUL */
}

static const char *
tok2strbuf(const struct tok *lp, const char *fmt,
		   const int v, char *buf, const size_t bufsize)
{
	if (lp != NULL)
	{
		while (lp->s != NULL)
		{
			if (lp->v == v)
				return (lp->s);
			++lp;
		}
	}
	if (fmt == NULL)
		fmt = "#%d";

	(void)snprintf(buf, bufsize, fmt, v);
	return (const char *)buf;
}

const char *
tok2str(const struct tok *lp, const char *fmt, const int v)
{
	static char buf[4][TOKBUFSIZE];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx + 1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}

static char *
bittok2str_internal(const struct tok *lp, const char *fmt,
					const int v, const char *sep)
{
	static char buf[1024 + 1]; /* our string buffer */
	char *bufp = buf;
	size_t space_left = sizeof(buf), string_size;
	const char *sepstr = "";

	while (lp != NULL && lp->s != NULL)
	{
		if (lp->v && (v & lp->v) == lp->v)
		{
			/* ok we have found something */
			if (space_left <= 1)
				return (buf); /* only enough room left for NUL, if that */
			string_size = strlcpy(bufp, sepstr, space_left);
			if (string_size >= space_left)
				return (buf); /* we ran out of room */
			bufp += string_size;
			space_left -= string_size;
			if (space_left <= 1)
				return (buf); /* only enough room left for NUL, if that */
			string_size = strlcpy(bufp, lp->s, space_left);
			if (string_size >= space_left)
				return (buf); /* we ran out of room */
			bufp += string_size;
			space_left -= string_size;
			sepstr = sep;
		}
		lp++;
	}

	if (bufp == buf)
		/* bummer - lets print the "unknown" message as advised in the fmt string if we got one */
		(void)snprintf(buf, sizeof(buf), fmt == NULL ? "#%08x" : fmt, v);
	return (buf);
}

char *
bittok2str(const struct tok *lp, const char *fmt, const int v)
{
	return (bittok2str_internal(lp, fmt, v, ", "));
}

/* The function enforces the array index to be 8-bit. */
const char *
netdb_protoname(const uint8_t protoid)
{
	return netdb_protocol_names[protoid];
}

/*
 * Convert a bit token value to a string; use "fmt" if not found.
 * this is useful for parsing bitfields, the output strings are not separated.
 */
char *
bittok2str_nosep(const struct tok *lp, const char *fmt, const int v)
{
	return (bittok2str_internal(lp, fmt, v, ""));
}

const char *
addrtostr (const void *src, char *dst, size_t size)
{
    const char *srcaddr = (const char *)src;
    const char digits[] = "0123456789";
    int i;
    const char *orig_dst = dst;

    if (size < INET_ADDRSTRLEN) {
		return NULL;
    }
    for (i = 0; i < 4; ++i) {
	int n = *srcaddr++;
	int non_zerop = 0;

	if (non_zerop || n / 100 > 0) {
	    *dst++ = digits[n / 100];
	    n %= 100;
	    non_zerop = 1;
	}
	if (non_zerop || n / 10 > 0) {
	    *dst++ = digits[n / 10];
	    n %= 10;
	    non_zerop = 1;
	}
	*dst++ = digits[n];
	if (i != 3)
	    *dst++ = '.';
    }
    *dst++ = '\0';
    return orig_dst;
}

/*
 * Convert IPv6 binary address into presentation (printable) format.
 */
const char *
addrtostr6(const void *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	const char *srcaddr = (const char *)src;
	char *dp;
	size_t space_left, added_space;
	int snprintfed;
	struct
	{
		int base;
		int len;
	} best, cur;
	uint16_t words[IN6ADDRSZ / INT16SZ];
	int i;

	/* Preprocess:
	 *  Copy the input (bytewise) array into a wordwise array.
	 *  Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
		words[i] = (srcaddr[2 * i] << 8) | srcaddr[2 * i + 1];

	best.len = 0;
	best.base = -1;
	cur.len = 0;
	cur.base = -1;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
	{
		if (words[i] == 0)
		{
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		}
		else if (cur.base != -1)
		{
			if (best.base == -1 || cur.len > best.len)
				best = cur;
			cur.base = -1;
		}
	}
	if ((cur.base != -1) && (best.base == -1 || cur.len > best.len))
		best = cur;
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/* Format the result.
	 */
	dp = dst;
	space_left = size;
#define APPEND_CHAR(c)       \
	{                        \
		if (space_left == 0) \
		{                    \
			return (NULL);   \
		}                    \
		*dp++ = c;           \
		space_left--;        \
	}
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
	{
		/* Are we inside the best run of 0x00's?
		 */
		if (best.base != -1 && i >= best.base && i < (best.base + best.len))
		{
			if (i == best.base)
				APPEND_CHAR(':');
			continue;
		}

		/* Are we following an initial run of 0x00s or any real hex?
		 */
		if (i != 0)
			APPEND_CHAR(':');

		/* Is this address an encapsulated IPv4?
		 */
		if (i == 6 && best.base == 0 &&
			(best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
		{
			if (!addrtostr(srcaddr + 12, dp, space_left))
			{
				return (NULL);
			}
			added_space = strlen(dp);
			dp += added_space;
			space_left -= added_space;
			break;
		}
		snprintfed = snprintf(dp, space_left, "%x", words[i]);
		if (snprintfed < 0)
			return (NULL);
		if ((size_t)snprintfed >= space_left)
		{
			return (NULL);
		}
		dp += snprintfed;
		space_left -= snprintfed;
	}

	/* Was it a trailing run of 0x00's?
	 */
	if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
		APPEND_CHAR(':');
	APPEND_CHAR('\0');

	return (dst);
}
