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
#define ND_PRINT(...) (ndo->ndo_printf)(ndo, __VA_ARGS__)
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

#define GET_U_1(p) get_u_1(ndo, (const char *)(p))
static inline uint8_t
get_u_1(netdissect_options *ndo, const char *p)
{
	return EXTRACT_U_1(p);
}

void pretty_print_packet(netdissect_options *ndo,
	 const struct pcap_pkthdr *h, const char *sp,
     int packets_captured);

void ndo_set_function_pointers(netdissect_options *ndo);