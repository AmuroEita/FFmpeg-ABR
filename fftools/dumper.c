/*
   ========================================================================================================
     Title  - Network Packet Parser
        ---------------------------------------------------------------------------------------------------
     Date   - 5th June 2014
        ---------------------------------------------------------------------------------------------------
     Brief Description

     -This is a menu driver program wherein you get the summary of all the packets or a single packet
     for inspection. 
     -Separate modules have been created to display the details of each header.
      -----------------------------------------------------------------------------------------------------
     Note

     -This code works for both the tcp.pcap and the arp.pcap files.
     -The name of the file has to been as a command line argument
   =========================================================================================================
*/

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include "print.h"

#define PCAP_ERRBUF_SIZE 256

#define PLURAL_SUFFIX(n) \
	(((n) != 1) ? "s" : "")

static int packets_captured;
static pcap_t *pd;

static void 
test (char *user, const struct pcap_pkthdr *h, const char *sp)
{
	static int count = 1;
    fprintf(stdout,"%d, ",count);
    fflush(stdout);
    count++;
}

static void
print_packet(char *user, const struct pcap_pkthdr *h, const char *sp)
{
	++packets_captured;
	pretty_print_packet((netdissect_options *)user, h, sp, packets_captured);
}

void dumper()
{
    
}

static char *
copy_argv(char **argv)
{
	char **p;
	size_t len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == NULL)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL)
		error("%s: malloc", __func__);

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}

int optind, opterr = 1, optopt;

static void
info(int verbose)
{
	struct pcap_stat stats;

	(void)fprintf(stderr, "%u packet%s captured", packets_captured,
	    PLURAL_SUFFIX(packets_captured));
	if (!verbose)
		fputs(", ", stderr);
	else
		putc('\n', stderr);
	(void)fprintf(stderr, "%u packet%s received by filter", stats.ps_recv,
	    PLURAL_SUFFIX(stats.ps_recv));
	if (!verbose)
		fputs(", ", stderr);
	else
		putc('\n', stderr);
	(void)fprintf(stderr, "%u packet%s dropped by kernel", stats.ps_drop,
	    PLURAL_SUFFIX(stats.ps_drop));
	if (stats.ps_ifdrop != 0) {
		if (!verbose)
			fputs(", ", stderr);
		else
			putc('\n', stderr);
		(void)fprintf(stderr, "%u packet%s dropped by interface\n",
		    stats.ps_ifdrop, PLURAL_SUFFIX(stats.ps_ifdrop));
	} else
		putc('\n', stderr);
}

int main()
{
	int cnt, op, i;
	bpf_u_int32 localnet = 0, netmask = 0;
	char *cp, *infile, *filter_exp, *device;
	char *endp;
	pcap_handler callback;
	int dlt;
	const char *dlt_name;
	struct bpf_program fcode;

	char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	netdissect_options Ndo;
	netdissect_options *ndo = &Ndo;

	if (nd_init(ebuf, sizeof(ebuf)) == -1)
		error("%s", ebuf);

	memset(ndo, 0, sizeof(*ndo));
	ndo_set_function_pointers(ndo);

	cnt = -1;
	device = NULL;
	dlt = -1;

	ndo->ndo_snaplen = 0;

	device = "wlp0s20f3";

	pd = pcap_open_live(device, BUFSIZ, 0, -1, ebuf);

	filter_exp = "tcp dst port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420";
	// filter_exp = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

	if (pcap_compile(pd, &fcode, filter_exp, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));

	dlt = pcap_datalink(pd);
	ndo->ndo_if_printer = get_if_printer(dlt);

	callback = print_packet;
	pcap_userdata = (char *)ndo;

	/*
	* Live capture (if -V was specified, we set RFileName
	* to a file from the -V file).  Print a message to
	* the standard error on UN*X.
	*/
	dlt = pcap_datalink(pd);
	dlt_name = pcap_datalink_val_to_name(dlt);
	(void)fprintf(stderr, "listening on %s", device);
	(void)fprintf(stderr, ", link-type %u\n", dlt);
	
	pcap_loop(pd, cnt, callback, pcap_userdata);
	
	fprintf(stdout, "%u packet%s\n", packets_captured,
		PLURAL_SUFFIX(packets_captured));

	free(filter_exp);
	pcap_freecode(&fcode);
}
