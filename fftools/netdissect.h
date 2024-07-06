#ifndef netdissect_h
#define netdissect_h
#endif
// 

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

#define ND_BYTES_AVAILABLE_AFTER(p) ((const u_char *)(p) < ndo->ndo_packetp ? 0 : ND_BYTES_BETWEEN((p), ndo->ndo_snapend))

#define ND_PRINT(...) (ndo->ndo_printf)(ndo, __VA_ARGS__)

#define MAC48_LEN	6U		/* length of MAC addresses */
typedef unsigned char nd_mac48[MAC48_LEN];

typedef unsigned char nd_uint16_t[2];

#define EXTRACT_BE_U_3(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 0)))
                
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

typedef struct nd_mem_chunk {
	void *prev_mem_p;
	/* variable size data */
} nd_mem_chunk_t;

struct lladdr_info {
	const char *(*addr_string)(netdissect_options *, const char *);
	const char *addr;
};

#define OUI_ENCAP_ETHER 0x000000  /* encapsulated Ethernet */

struct tok {
	int v;		/* value */
	const char *s;		/* string */
};

#define ETHERTYPE_MACSEC	0x88e5

extern void ether_if_print IF_PRINTER_ARGS;

/* Initialize netdissect. */
int nd_init(char *, size_t);

void nd_free_all(netdissect_options *);

void nd_pop_all_packet_info(netdissect_options *);