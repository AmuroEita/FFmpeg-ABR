#include "print.h"

enum date_flag { WITHOUT_DATE = 0, WITH_DATE = 1 };
enum time_flag { UTC_TIME = 0, LOCAL_TIME = 1 };

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

/*
 * Print the timestamp
 */
void
ts_print(netdissect_options *ndo,
         const struct timeval *tvp)
{
	ts_date_hmsfrac_print(ndo, tvp, WITHOUT_DATE, LOCAL_TIME);
	ND_PRINT(" ");
}

void
pretty_print_packet(netdissect_options *ndo, const struct pcap_pkthdr *h,
		    const char *sp, int packets_captured)
{
	int hdrlen = 0;
	int invalid_header = 0;

	if (ndo->ndo_print_sampling && packets_captured % ndo->ndo_print_sampling != 0)
		return;

	if (ndo->ndo_packet_number)
		ND_PRINT("%5u  ", packets_captured);

	if (ndo->ndo_lengths)
		ND_PRINT("caplen %u len %u ", h->caplen, h->len);

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

	/*
	 * At this point:
	 *   capture length != 0,
	 *   packet length != 0,
	 *   capture length <= MAXIMUM_SNAPLEN,
	 *   packet length <= MAXIMUM_SNAPLEN,
	 *   packet length >= capture length.
	 *
	 * Currently, there is no D-Bus printer, thus no need for
	 * bigger lengths.
	 */

	/*
	 * The header /usr/include/pcap/pcap.h in OpenBSD declares h->ts as
	 * struct bpf_timeval, not struct timeval. The former comes from
	 * /usr/include/net/bpf.h and uses 32-bit unsigned types instead of
	 * the types used in struct timeval.
	 */
	struct timeval tvbuf;
	tvbuf.tv_sec = h->ts.tv_sec;
	tvbuf.tv_usec = h->ts.tv_usec;
	ts_print(ndo, &tvbuf);

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

	/*
	 * Empty the stack of packet information, freeing all pushed buffers;
	 * if we got here by a printer quitting, we need to release anything
	 * that didn't get released because we longjmped out of the code
	 * before it popped the packet information.
	 */
	nd_pop_all_packet_info(ndo);

	ND_PRINT("\n");
	nd_free_all(ndo);
}