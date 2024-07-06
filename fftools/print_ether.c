#include "netdissect.h"

#define ETHER_HDRLEN 14
#define BUFSIZE 128
#define TOKBUFSIZE 128
#define	MAX_ETHERNET_LENGTH_VAL	1500
#define HASHNAMESIZE 4096

#define	ETHERTYPE_IP		0x0800	
#define ETHERTYPE_IPV6		0x86dd
#define ETHERTYPE_JUMBO     0x8870
#define	ETHERTYPE_ARISTA    0xd28b 

#define GET_MAC48_STRING(p) get_mac48_string(ndo, (const char *)(p))

#define GET_BE_U_2(p) get_be_u_2(ndo, (const char *)(p))

#define IS_NOT_NEGATIVE(x) (((x) > 0) || ((x) == 0))

#define ND_TTEST_LEN(p, l) \
  (IS_NOT_NEGATIVE(l) && \
	((uintptr_t)ndo->ndo_snapend - (l) <= (uintptr_t)ndo->ndo_snapend && \
         (uintptr_t)(p) <= (uintptr_t)ndo->ndo_snapend - (l)))

static const char hex[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

const struct tok ethertype_values[] = {
    { ETHERTYPE_IP,		"IPv4" },
    { ETHERTYPE_IPV6,	"IPv6" },
    { 0, NULL}
};

struct	ether_header {
	nd_mac48	ether_dhost;
	nd_mac48	ether_shost;
	nd_uint16_t	ether_length_type;
};

struct enamemem {
	short e_addr0;
	short e_addr1;
	short e_addr2;
	const char *e_name;
	char *e_nsap;			/* used only for nsaptable[] */
	struct enamemem *e_nxt;
};

static struct enamemem enametable[HASHNAMESIZE];

const struct tok oui_values[] = {
    { OUI_ENCAP_ETHER, "Ethernet" },
    { 0, NULL }
};

static inline uint16_t
EXTRACT_BE_U_2(const void *p)
{
	return ((uint16_t)ntohs(*(const uint16_t *)(p)));
}

static inline char *
octet_to_hex(char *cp, uint8_t octet)
{
	*cp++ = hex[(octet >> 4) & 0xf];
	*cp++ = hex[(octet >> 0) & 0xf];
	return (cp);
}

static const char *
tok2strbuf(const struct tok *lp, const char *fmt,
	   const int v, char *buf, const size_t bufsize)
{
	if (lp != NULL) {
		while (lp->s != NULL) {
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
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}

static void
ether_type_print(netdissect_options *ndo, uint16_t type)
{
	if (!ndo->ndo_qflag)
		ND_PRINT("ethertype %s (0x%04x)",
			 tok2str(ethertype_values, "Unknown", type), type);
	else
		ND_PRINT("%s",
			 tok2str(ethertype_values, "Unknown Ethertype (0x%04x)", type));
}

static struct enamemem *
lookup_emem(netdissect_options *ndo, const char *ep)
{
	int i, j, k;
	struct enamemem *tp;

	k = (ep[0] << 8) | ep[1];
	j = (ep[2] << 8) | ep[3];
	i = (ep[4] << 8) | ep[5];

	tp = &enametable[(i ^ j) & (HASHNAMESIZE-1)];
	while (tp->e_nxt)
		if (tp->e_addr0 == i &&
		    tp->e_addr1 == j &&
		    tp->e_addr2 == k)
			return tp;
		else
			tp = tp->e_nxt;
	tp->e_addr0 = (short)i;
	tp->e_addr1 = (short)j;
	tp->e_addr2 = (short)k;
	tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));

	return tp;
}

const char *
mac48_string(netdissect_options *ndo, const uint8_t *ep)
{
	int i;
	char *cp;
	struct enamemem *tp;
	int oui;
	char buf[BUFSIZE];

	tp = lookup_emem(ndo, ep);
	if (tp->e_name)
		return (tp->e_name);

	cp = buf;
	oui = EXTRACT_BE_U_3(ep);
	cp = octet_to_hex(cp, *ep++);
	for (i = 5; --i >= 0;) {
		*cp++ = ':';
		cp = octet_to_hex(cp, *ep++);
	}

	if (!ndo->ndo_nflag) {
		snprintf(cp, BUFSIZE - (2 + 5*3), " (oui %s)",
		    tok2str(oui_values, "Unknown", oui));
	} else
		*cp = '\0';
		
	return (tp->e_name);
}

void
nd_trunc_longjmp(netdissect_options *ndo)
{
	longjmp(ndo->ndo_early_end, 1);
}

static inline uint16_t
get_be_u_2(netdissect_options *ndo, const char *p)
{
	return EXTRACT_BE_U_2(p);
}

static inline const char *
get_mac48_string(netdissect_options *ndo, const uint8_t *p)
{
	if (!ND_TTEST_LEN(p, MAC48_LEN))
			nd_trunc_longjmp(ndo);
	return mac48_string(ndo, p);
}

static void
ether_addresses_print(netdissect_options *ndo, const char *src,
		      const char *dst)
{
	ND_PRINT("%s > %s, ",
		 GET_MAC48_STRING(src), GET_MAC48_STRING(dst));
}

int
ethertype_print(netdissect_options *ndo,
		short ether_type, const char *p,
		int length, int caplen,
		const struct lladdr_info *src, const struct lladdr_info *dst)
{
	switch (ether_type) {

	case ETHERTYPE_IP:
		// printf("\n\nETHER PRINT ----  %s  ---- \n\n", p);
		// ip_print(ndo, p, length);
		return (1);

	case ETHERTYPE_IPV6:
		// ip6_print(ndo, p, length);
		return (1);
		/* default_print for now */
	default:
		return (0);
	}
}


static int
ether_common_print(netdissect_options *ndo, const char *p, int length,
    int caplen,
    void (*print_switch_tag)(netdissect_options *ndo, const char *),
    int switch_tag_len,
    void (*print_encap_header)(netdissect_options *ndo, const char *),
    const char *encap_header_arg)
{
	const struct ether_header *ehp;
	int orig_length;
	int hdrlen;
	short length_type;
	int printed_length;
	int llc_hdrlen;
	struct lladdr_info src, dst;

	if (length < caplen) {
		ND_PRINT("[length %u < caplen %u]", length, caplen);
		return length;
	}
	if (caplen < ETHER_HDRLEN + switch_tag_len) {
		return caplen;
	}

	if (print_encap_header != NULL)
		(*print_encap_header)(ndo, encap_header_arg);

	orig_length = length;

	/*
	 * Get the source and destination addresses, skip past them,
	 * and print them if we're printing the link-layer header.
	 */
	ehp = (const struct ether_header *)p;
	src.addr = ehp->ether_shost;
	src.addr_string = mac48_string;
	dst.addr = ehp->ether_dhost;
	dst.addr_string = mac48_string;

	length -= 2*MAC48_LEN;
	caplen -= 2*MAC48_LEN;
	p += 2*MAC48_LEN;
	hdrlen = 2*MAC48_LEN;

	if (ndo->ndo_eflag)
		ether_addresses_print(ndo, src.addr, dst.addr);

	/*
	 * Print the switch tag, if we have one, and skip past it.
	 */
	if (print_switch_tag != NULL)
		(*print_switch_tag)(ndo, p);

	length -= switch_tag_len;
	caplen -= switch_tag_len;
	p += switch_tag_len;
	hdrlen += switch_tag_len;

	/*
	 * Get the length/type field, skip past it, and print it
	 * if we're printing the link-layer header.
	 */
recurse:
	length_type = GET_BE_U_2(p);

	length -= 2;
	caplen -= 2;
	p += 2;
	hdrlen += 2;

	if (!(length_type <= MAX_ETHERNET_LENGTH_VAL || 
		length_type == ETHERTYPE_JUMBO || 
		length_type == ETHERTYPE_ARISTA)) { 
		/*
		 * It's a type field with some other value.
		 */
		if (ndo->ndo_eflag) {
			ether_type_print(ndo, length_type);
			if (!printed_length)
				ND_PRINT(", length %u: ", orig_length);
			else
				ND_PRINT(", ");
		}
		if (ethertype_print(ndo, length_type, p, length, caplen, &src, &dst) == 0) {
			/* type not known, print raw packet */
			if (!ndo->ndo_eflag) {
				/*
				 * We didn't print the full link-layer
				 * header, as -e wasn't specified, so
				 * print only the source and destination
				 * MAC addresses and the final Ethernet
				 * type.
				 */
				ether_addresses_print(ndo, src.addr, dst.addr);
				ether_type_print(ndo, length_type);
				ND_PRINT(", length %u: ", orig_length);
			}
		}
	}
invalid:
	return hdrlen;
}

int
ether_print(netdissect_options *ndo,
	    const char *p, int length, int caplen,
	    void (*print_encap_header)(netdissect_options *ndo, const char *),
	    const char *encap_header_arg)
{
	ndo->ndo_protocol = "ether";
	return ether_common_print(ndo, p, length, caplen, NULL, 0,
				  print_encap_header, encap_header_arg);
}

void
ether_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
	       const char *p)
{
	ndo->ndo_protocol = "ether";
	ndo->ndo_ll_hdr_len +=
		ether_print(ndo, p, h->len, h->caplen, NULL, NULL);
}