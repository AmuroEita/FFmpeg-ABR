#ifndef netdissect_h
#define netdissect_h
#endif

#include <setjmp.h>
#include <pcap.h>

#define MAXIMUM_SNAPLEN	262144

#define PRINTFLIKE_FUNCPTR(x,y) __attribute__((__format__(__printf__,x,y)))

#define __SIZE_TYPE__ long unsigned int
typedef __SIZE_TYPE__ size_t;

typedef struct netdissect_options netdissect_options;

#define IF_PRINTER_ARGS (netdissect_options *, const struct pcap_pkthdr *, const char *)
typedef void (*if_printer) IF_PRINTER_ARGS;

#define ND_BYTES_BETWEEN(p1, p2) ((const char *)(p1) >= (const char *)(p2) ? 0 : ((int)(((const char *)(p2)) - (const char *)(p1))))

#define ND_BYTES_AVAILABLE_AFTER(p) ((const char *)(p) < ndo->ndo_packetp ? 0 : ND_BYTES_BETWEEN((p), ndo->ndo_snapend))

#define ND_PRINT(...) (ndo->ndo_printf)(ndo, __VA_ARGS__)

#define MAC48_LEN	6U		/* length of MAC addresses */
typedef unsigned char nd_mac48[MAC48_LEN];

#define UNALIGNED_MEMCPY(p, q, l)	memcpy((p), (q), (l))
#define UNALIGNED_MEMCMP(p, q, l)	memcmp((p), (q), (l))

#define EXTRACT_BE_U_3(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0)))

typedef unsigned char nd_uint8_t[1];
typedef unsigned char nd_uint16_t[2];
typedef unsigned char nd_uint32_t[4];

typedef unsigned char nd_ipv6[16];

struct netdissect_saved_packet_info {
    char *ndspi_buffer;					/* pointer to allocated buffer data */
    const char *ndspi_packetp;				/* saved beginning of data */
    const char *ndspi_snapend;				/* saved end of data */
    struct netdissect_saved_packet_info *ndspi_prev;	/* previous buffer on the stack */
};

struct netdissect_options {
    int ndo_bflag;		/* print 4 byte ASes in ASDOT notation */
    int ndo_eflag;		/* print ethernet header */
    int ndo_fflag;		/* don't translate "foreign" IP address */
    int ndo_Kflag;		/* don't check IP, TCP or UDP checksums */
    int ndo_nflag;		/* leave addresses as numbers */
    int ndo_Nflag;		/* remove domains from printed host names */
    int ndo_qflag;		/* quick (shorter) output */
    int ndo_Sflag;		/* print raw TCP sequence numbers */
    int ndo_tflag;		/* print packet arrival time */
    int ndo_uflag;		/* Print undecoded NFS handles */
    int ndo_vflag;		/* verbosity level */
    int ndo_xflag;		/* print packet in hex */
    int ndo_Xflag;		/* print packet in hex/ASCII */
    int ndo_Aflag;		/* print packet only in ASCII observing TAB,
                    * LF, CR and SPACE as graphical chars
                    */
    int ndo_Hflag;		/* dissect 802.11s draft mesh standard */
    const char *ndo_protocol;	/* protocol */
    jmp_buf ndo_early_end;	/* jmp_buf for setjmp()/longjmp() */
    void *ndo_last_mem_p;		/* pointer to the last allocated memory chunk */
    int ndo_packet_number;	/* print a packet number in the beginning of line */
    int ndo_lengths;		/* print packet header caplen and len */
    int ndo_print_sampling;	/* print every Nth packet */
    int ndo_suppress_default_print; /* don't use default_print() for unknown packet types */
    int ndo_tstamp_precision;	/* requested time stamp precision */
    const char *program_name;	/* Name of the program using the library */

    char *ndo_espsecret;

    char *ndo_sigsecret;		/* Signature verification secret key */

    int   ndo_packettype;	/* as specified by -T */

    int   ndo_snaplen;
    int   ndo_ll_hdr_len;	/* link-layer header length */

    /* stack of saved packet boundary and buffer information */
    struct netdissect_saved_packet_info *ndo_packet_info_stack;

    /*global pointers to beginning and end of current packet (during printing) */
    const char *ndo_packetp;
    const char *ndo_snapend;

    /* pointer to the if_printer function */
    if_printer ndo_if_printer;

    /* pointer to void function to output stuff */
    void (*ndo_default_print)(netdissect_options *,
			    const char *bp, int length);

    /* pointer to function to do regular output */
    int  (*ndo_printf)(netdissect_options *,
		     const char *fmt, ...)
		     PRINTFLIKE_FUNCPTR(2, 3);
};

#define EXTRACT_U_1(p)	((uint8_t)(*(p)))

#define GET_U_1(p) get_u_1(ndo, (const char *)(p))

static inline uint8_t
get_u_1(netdissect_options *ndo, const char *p)
{
	return EXTRACT_U_1(p);
}

typedef struct nd_mem_chunk {
	void *prev_mem_p;
	/* variable size data */
} nd_mem_chunk_t;

struct lladdr_info {
	const char *(*addr_string)(netdissect_options *, const char *);
	const char *addr;
};

#define OUI_ENCAP_ETHER 0x000000  /* encapsulated Ethernet */

#define ETHERTYPE_MACSEC	0x88e5

static inline uint16_t
EXTRACT_BE_U_2(const void *p)
{
	return ((uint16_t)ntohs(*(const uint16_t *)(p)));
}

static inline uint16_t
get_be_u_2(netdissect_options *ndo, const char *p)
{
	return EXTRACT_BE_U_2(p);
}

#define GET_BE_U_2(p) get_be_u_2(ndo, (const char *)(p))

static inline uint32_t
EXTRACT_BE_U_4(const void *p)
{
	return ((uint32_t)ntohl(*(const uint32_t *)(p)));
}

static inline uint32_t
get_be_u_4(netdissect_options *ndo, const char *p)
{
	return EXTRACT_BE_U_4(p);
}

#define GET_BE_U_4(p) get_be_u_4(ndo, (const char *)(p))

#define ND_ICHECKMSG_U(message, expression_1, operator, expression_2) \
if ((expression_1) operator (expression_2)) { \
ND_PRINT(" [%s %u %s %u]", (message), (expression_1), (#operator), (expression_2)); \
goto invalid; \
}

#define ND_ICHECKMSG_ZU(message, expression_1, operator, expression_2) \
if ((expression_1) operator (expression_2)) { \
ND_PRINT(" [%s %u %s %zu]", (message), (expression_1), (#operator), (expression_2)); \
goto invalid; \
}

#define ND_ICHECK_ZU(expression_1, operator, expression_2) \
ND_ICHECKMSG_ZU((#expression_1), (expression_1), operator, (expression_2))

extern void ether_if_print IF_PRINTER_ARGS;

/* Initialize netdissect. */
int nd_init(char *, size_t);

void nd_free_all(netdissect_options *);

void nd_pop_all_packet_info(netdissect_options *);

int nd_push_snaplen(netdissect_options *, const char *, const int);

const char *ipaddr_string(netdissect_options *, const char *);

static inline const char *
get_ipaddr_string(netdissect_options *ndo, const char *p)
{
        return ipaddr_string(ndo, p);
}

#define GET_IPADDR_STRING(p) get_ipaddr_string(ndo, (const char *)(p))

const char *ip6addr_string(netdissect_options *, const char *);

static inline const char *
get_ip6addr_string(netdissect_options *ndo, const char *p)
{
        return ip6addr_string(ndo, p);
}

#define GET_IP6ADDR_STRING(p) get_ip6addr_string(ndo, (const char *)(p))

#define ND_TTEST_LEN(p, l) \
  (IS_NOT_NEGATIVE(l) && \
	((uintptr_t)ndo->ndo_snapend - (l) <= (uintptr_t)ndo->ndo_snapend && \
         (uintptr_t)(p) <= (uintptr_t)ndo->ndo_snapend - (l)))

#define ND_TTEST_2(p) ND_TTEST_LEN((p), 2)

/* True if "*(p)" was captured */
#define ND_TTEST_SIZE(p) ND_TTEST_LEN(p, sizeof(*(p)))

#define ND_TCHECK_LEN(p, l) if (!ND_TTEST_LEN(p, l)) goto trunc

#define ND_TCHECK_SIZE(p) ND_TCHECK_LEN(p, sizeof(*(p)))

#define HASHNAMESIZE 4096

struct hnamemem {
	uint32_t addr;
	const char *name;
	struct hnamemem *nxt;
};

static struct hnamemem hnametable[HASHNAMESIZE];

struct h6namemem {
	nd_ipv6 addr;
	char *name;
	struct h6namemem *nxt;
};

static struct h6namemem h6nametable[HASHNAMESIZE];

#define IS_NOT_NEGATIVE(x) (((x) > 0) || ((x) == 0))

void nd_trunc_longjmp(netdissect_options *);

#define ND_TCHECK_LEN(p, l) if (!ND_TTEST_LEN(p, l)) nd_trunc_longjmp(ndo)

void nd_pop_packet_info(netdissect_options *ndo);

struct hnamemem *newhnamemem(netdissect_options *ndo);

void ip_print(netdissect_options *ndo, const char *bp, const int length);

void tcp_print(netdissect_options *ndo, const char *bp, int length, const char *bp2, int fragmented);

int ether_print(netdissect_options *ndo, const char *p, int length, int caplen, 
        void (*print_encap_header)(netdissect_options *ndo, const char *), const char *encap_header_arg);

void pretty_print_packet(netdissect_options *ndo, const struct pcap_pkthdr *h, const char *sp, int packets_captured);

if_printer get_if_printer(int type);

void ndo_set_function_pointers(netdissect_options *ndo);