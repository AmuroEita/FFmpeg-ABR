#ifndef print_h
#define print_h
#endif

#include <stdarg.h>
#include <pcap.h>

#include "netdissect.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define PRINTFLIKE(x,y) __attribute__((__format__(__printf__,x,y)))
#define FORMAT_STRING(p) p

#define ND_MICRO_PER_SEC 1000000
#define ND_NANO_PER_SEC 1000000000

#define ASCII_LINELENGTH 300
#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE \
		(HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)

#define ND_ASCII_ISGRAPH(c)	((c) > 0x20 && (c) <= 0x7E)

#define netdissect_timevalcmp(tvp, uvp, cmp)   \
	(((tvp)->tv_sec == (uvp)->tv_sec) ?    \
	 ((tvp)->tv_usec cmp (uvp)->tv_usec) : \
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define netdissect_timevalsub(tvp, uvp, vvp, nano_prec)            \
	do {                                                       \
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;     \
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;  \
		if ((vvp)->tv_usec < 0) {                          \
		    (vvp)->tv_sec--;                               \
		    (vvp)->tv_usec += (nano_prec ? ND_NANO_PER_SEC : \
				       ND_MICRO_PER_SEC);          \
		}                                                  \
	} while (0)


#define NORETURN __attribute((noreturn))
#define ND_TRUNCATED 1

#define EXTRACT_U_1(p)	((uint8_t)(*(p)))

#define ND_BYTES_BETWEEN(p1, p2) ((const char *)(p1) >= (const char *)(p2) ? 0 : ((int)(((const char *)(p2)) - (const char *)(p1))))

#define ND_BYTES_AVAILABLE_AFTER(p) ((const u_char *)(p) < ndo->ndo_packetp ? 0 : ND_BYTES_BETWEEN((p), ndo->ndo_snapend))

#define GET_U_1(p) get_u_1(ndo, (const char *)(p))
static inline uint8_t
get_u_1(netdissect_options *ndo, const char *p)
{
	return EXTRACT_U_1(p);
}

#define IF_PRINTER_ARGS (netdissect_options *, const struct pcap_pkthdr *, const char *)

typedef void (*if_printer) IF_PRINTER_ARGS;

#define ND_ASCII_TOUPPER(c)	(((c) >= 'a' && (c) <= 'z') ? (c) - 'a' + 'A' : (c))

void pretty_print_packet(netdissect_options *ndo,
	 const struct pcap_pkthdr *h, const char *sp,
     int packets_captured);

void ndo_set_function_pointers(netdissect_options *ndo);

void ascii_print(netdissect_options *, const char *, int);

if_printer get_if_printer(int type);


