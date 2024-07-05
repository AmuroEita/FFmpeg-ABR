#include <time.h>

#include "print.h"

#define DLT_EN10MB	1	/* Ethernet (10Mb) */

enum date_flag { WITHOUT_DATE = 0, WITH_DATE = 1 };
enum time_flag { UTC_TIME = 0, LOCAL_TIME = 1 };

struct printer {
	if_printer f;
	int type;
};

static const struct printer printers[] = {
	{ ether_if_print,	DLT_EN10MB },
	{ NULL,                 0 },
};

static void
hex_and_ascii_print_with_offset(netdissect_options *ndo, const char *indent,
				const char *cp, int length, int offset)
{
	int caplength;
	int i;
	int s1, s2;
	int nshorts;
	int truncated = 0;
	char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
	char asciistuff[ASCII_LINELENGTH+1], *asp;

	caplength = ND_BYTES_AVAILABLE_AFTER(cp);
	if (length > caplength) {
		length = caplength;
		truncated = TRUE;
	}
	nshorts = length / sizeof(short);
	i = 0;
	hsp = hexstuff; asp = asciistuff;
	while (nshorts != 0) {
		s1 = GET_U_1(cp);
		cp++;
		s2 = GET_U_1(cp);
		cp++;
		(void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
		    " %02x%02x", s1, s2);
		hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
		*(asp++) = (char)(ND_ASCII_ISGRAPH(s1) ? s1 : '.');
		*(asp++) = (char)(ND_ASCII_ISGRAPH(s2) ? s2 : '.');
		i++;
		if (i >= HEXDUMP_SHORTS_PER_LINE) {
			*hsp = *asp = '\0';
			ND_PRINT("%s0x%04x: %-*s  %s",
			    indent, offset, HEXDUMP_HEXSTUFF_PER_LINE,
			    hexstuff, asciistuff);
			i = 0; hsp = hexstuff; asp = asciistuff;
			offset += HEXDUMP_BYTES_PER_LINE;
		}
		nshorts--;
	}
	if (length & 1) {
		s1 = GET_U_1(cp);
		cp++;
		(void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
		    " %02x", s1);
		hsp += 3;
		*(asp++) = (char)(ND_ASCII_ISGRAPH(s1) ? s1 : '.');
		++i;
	}
	if (i > 0) {
		*hsp = *asp = '\0';
		ND_PRINT("%s0x%04x: %-*s  %s",
		     indent, offset, HEXDUMP_HEXSTUFF_PER_LINE,
		     hexstuff, asciistuff);
	}
}

void
hex_and_ascii_print(netdissect_options *ndo, const char *indent,
		    const char *cp, int length)
{
	hex_and_ascii_print_with_offset(ndo, indent, cp, length, 0);
}

static void
ndo_default_print(netdissect_options *ndo, const char *bp, int length)
{
	hex_and_ascii_print(ndo, "\n\t", bp, length); /* pass on lf and indentation string */
}

/* VARARGS */
static int PRINTFLIKE(2, 3)
ndo_printf(netdissect_options *ndo, FORMAT_STRING(const char *fmt), ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vfprintf(stdout, fmt, args);
	va_end(args);

	return (ret);
}

void
ndo_set_function_pointers(netdissect_options *ndo)
{
	ndo->ndo_default_print=ndo_default_print;
	ndo->ndo_printf=ndo_printf;
}

const char *
nd_format_time(char *buf, size_t bufsize, const char *format,
         const struct tm *timeptr)
{
	if (timeptr != NULL) {
		if (strftime(buf, bufsize, format, timeptr) != 0)
			return (buf);
		else
			return ("[nd_format_time() buffer is too small]");
	} else
		return ("[localtime() or gmtime() couldn't convert the date and time]");
}

static void
ts_date_hmsfrac_print(netdissect_options *ndo, const struct timeval *tv,
		      enum date_flag date_flag, enum time_flag time_flag)
{
	struct tm *tm;
	char timebuf[32];
	const char *timestr;

	if (tv->tv_sec < 0) {
		ND_PRINT("[timestamp < 1970-01-01 00:00:00 UTC]");
		return;
	}
	
	if (time_flag == LOCAL_TIME)
		tm = localtime(&tv->tv_sec);
	else
		tm = gmtime(&tv->tv_sec);

	if (date_flag == WITH_DATE) {
		timestr = nd_format_time(timebuf, sizeof(timebuf),
		    "%Y-%m-%d %H:%M:%S", tm);
	} else {
		timestr = nd_format_time(timebuf, sizeof(timebuf),
		    "%H:%M:%S", tm);
	}
	ND_PRINT("%s", timestr);

	ND_PRINT(".%06u", (unsigned)tv->tv_usec);
}

void
ascii_print(netdissect_options *ndo,
            const char *cp, int length)
{
	int caplength;
	char s;
	int truncated = FALSE;

	ndo->ndo_protocol = "ascii";
	caplength = ND_BYTES_AVAILABLE_AFTER(cp);
	if (length > caplength) {
		length = caplength;
		truncated = TRUE;
	}
	ND_PRINT("\n");
	while (length != 0) {
		s = GET_U_1(cp);
		cp++;
		length--;
		if (s == '\r') {
			/*
			 * Don't print CRs at the end of the line; they
			 * don't belong at the ends of lines on UN*X,
			 * and the standard I/O library will give us one
			 * on Windows so we don't need to print one
			 * ourselves.
			 *
			 * In the middle of a line, just print a '.'.
			 */
			if (length > 1 && GET_U_1(cp) != '\n')
				ND_PRINT(".");
		} else {
			if (!ND_ASCII_ISGRAPH(s) &&
			    (s != '\t' && s != ' ' && s != '\n'))
				ND_PRINT(".");
			else
				ND_PRINT("%c", s);
		}
	}
}

/*
 * Print the timestamp
 */
void
ts_print(netdissect_options *ndo,
         const struct timeval *tv)
{
	printf("ssssss ");

	struct tm *tm;
	char timebuf[32];
	const char *timestr;

	if (tv->tv_sec < 0) {
		printf("[timestamp < 1970-01-01 00:00:00 UTC]");
		return;
	}
	
	tm = localtime(&tv->tv_sec);

	timestr = nd_format_time(timebuf, sizeof(timebuf),
		    "%H:%M:%S", tm);

	printf("%s", timestr);
	printf(".%06u", (unsigned)tv->tv_usec);
	ND_PRINT(" ");
}

void
pretty_print_packet(netdissect_options *ndo, const struct pcap_pkthdr *h,
		    const char *sp, int packets_captured)
{
	int hdrlen = 0;
	int invalid_header = 0;

	/* Sanity checks on packet length / capture length */
	if (h->caplen == 0) {
		invalid_header = 1;
		ND_PRINT("[Invalid header: caplen==0");
	}
	if (h->len == 0) {
		if (!invalid_header) {
			invalid_header = 1;
			ND_PRINT("[Invalid header:");
		} else
			ND_PRINT(",");
		ND_PRINT(" len==0");
	} else if (h->len < h->caplen) {
		if (!invalid_header) {
			invalid_header = 1;
			ND_PRINT("[Invalid header:");
		} else
			ND_PRINT(",");
		ND_PRINT(" len(%u) < caplen(%u)", h->len, h->caplen);
	}
	if (h->caplen > MAXIMUM_SNAPLEN) {
		if (!invalid_header) {
			invalid_header = 1;
			ND_PRINT("[Invalid header:");
		} else
			ND_PRINT(",");
		ND_PRINT(" caplen(%u) > %u", h->caplen, MAXIMUM_SNAPLEN);
	}
	if (h->len > MAXIMUM_SNAPLEN) {
		if (!invalid_header) {
			invalid_header = 1;
			ND_PRINT("[Invalid header:");
		} else
			ND_PRINT(",");
		ND_PRINT(" len(%u) > %u", h->len, MAXIMUM_SNAPLEN);
	}
	if (invalid_header) {
		ND_PRINT("]\n");
		return;
	}

	struct timeval tv;
	tv.tv_sec = h->ts.tv_sec;
	tv.tv_usec = h->ts.tv_usec;

	struct tm *tm;
	char timebuf[64];

	if (tv.tv_sec < 0) {
		ND_PRINT("[timestamp < 1970-01-01 00:00:00 UTC]");
		return;
	}
	
	tm = localtime(&tv.tv_sec);

   	if (tm != NULL && strftime(timebuf, 64, "%H:%M:%S", tm) != 0)
		ND_PRINT("%s", timebuf);
	ND_PRINT(".%06u", (unsigned)tv.tv_usec);

	/*
	 * Printers must check that they're not walking off the end of
	 * the packet.
	 * Rather than pass it all the way down, we set this member
	 * of the netdissect_options structure.
	 */
	ndo->ndo_snapend = sp + h->caplen;
	ndo->ndo_packetp = sp;

	ndo->ndo_protocol = "";
	ndo->ndo_ll_hdr_len = 0;
	if (setjmp(ndo->ndo_early_end) == 0) {
		/* Print the packet. */
		(ndo->ndo_if_printer)(ndo, h, sp);
	} else {
		/* Print the full packet */
		ndo->ndo_ll_hdr_len = 0;
	}
	hdrlen = ndo->ndo_ll_hdr_len;

	nd_pop_all_packet_info(ndo);

	ndo->ndo_snapend = sp + h->caplen;
	ndo->ndo_packetp = sp;

	if (h->caplen > hdrlen)
		ascii_print(ndo, sp + hdrlen, h->caplen - hdrlen);

	ND_PRINT("\n");
	nd_free_all(ndo);
}

if_printer
lookup_printer(int type)
{
	const struct printer *p;

	for (p = printers; p->f; ++p)
		if (type == p->type)
			return p->f;
	return NULL;
}

void nd_print_protocol_caps(netdissect_options *ndo)
{
	const char *p;
        for (p = ndo->ndo_protocol; *p != '\0'; p++)
                ND_PRINT("%c", ND_ASCII_TOUPPER(*p));
}

void
unsupported_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
		     const char *p)
{
	ndo->ndo_protocol = "unsupported";
	nd_print_protocol_caps(ndo);
	hex_and_ascii_print(ndo, "\n\t", p, h->caplen);
}

if_printer
get_if_printer(int type)
{
	if_printer printer;

	printer = lookup_printer(type);
	if (printer == NULL)
		printer = unsupported_if_print;
	return printer;
}