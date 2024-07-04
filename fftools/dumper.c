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
#include <pcap.h>
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
	printf("----- testing ----- \n");
}

static void
print_packet(char *user, const struct pcap_pkthdr *h, const char *sp)
{
	++packets_captured;
	printf("-----\n");
	pretty_print_packet((netdissect_options *)user, h, sp, packets_captured);
}

static pcap_t *
open_interface(const char *device, netdissect_options *ndo, char *ebuf)
{
	pcap_t *pc;
	int status;
	char *cp;

	pc = pcap_create(device, ebuf);
	if (pc == NULL) {
		/*
		 * If this failed with "No such device", that means
		 * the interface doesn't exist; return NULL, so that
		 * the caller can see whether the device name is
		 * actually an interface index.
		 */
		if (strstr(ebuf, "No such device") != NULL)
			return (NULL);
		error("%s", ebuf);
	}

	if (ndo->ndo_snaplen != 0) {
		/*
		 * A snapshot length was explicitly specified;
		 * use it.
		 */
		status = pcap_set_snaplen(pc, ndo->ndo_snaplen);
		if (status != 0)
			error("%s: Can't set snapshot length: %s",
			    device, pcap_statustostr(status));
	}

	status = pcap_activate(pc);
	if (status < 0) {
		/*
		 * pcap_activate() failed.
		 */
		cp = pcap_geterr(pc);
		if (status == PCAP_ERROR)
			error("%s", cp);
		else if (status == PCAP_ERROR_NO_SUCH_DEVICE) {
			/*
			 * Return an error for our caller to handle.
			 */
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s: %s\n(%s)",
			    device, pcap_statustostr(status), cp);
		} else if (status == PCAP_ERROR_PERM_DENIED && *cp != '\0')
			error("%s: %s\n(%s)", device,
			    pcap_statustostr(status), cp);

		else
			error("%s: %s", device,
			    pcap_statustostr(status));
		pcap_close(pc);
		return (NULL);
	} else if (status > 0) {
		/*
		 * pcap_activate() succeeded, but it's warning us
		 * of a problem it had.
		 */
		cp = pcap_geterr(pc);
	}

	return (pc);
}

void dumper()
{
    int status, cnt;
    char *pcap_userdata, *device;
    pcap_handler callback;
    char ebuf[PCAP_ERRBUF_SIZE];

    device = NULL;
    
    netdissect_options Ndo;
	netdissect_options *ndo = &Ndo;

    /*
	 * Initialize the netdissect code.
	 */
	if (nd_init(ebuf, sizeof(ebuf)) == -1)
		error("%s", ebuf);

	memset(ndo, 0, sizeof(*ndo));
	ndo_set_function_pointers(ndo);

    device = pcap_lookupdev(ebuf);
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", ebuf);
        return;
    }

    printf("Device: %s\n", device);

    pd = open_interface(device, ndo, ebuf);
    if (pd == NULL) {
        printf("%s\n", ebuf);
        return;
    }

	printf("Point A \n");

    callback = print_packet;
	// callback = test;
	pcap_userdata = (char *)ndo;

	printf("Point B \n");

    do {
		printf("Point C start \n");
        status = pcap_loop(pd, cnt, callback, pcap_userdata);
		printf("Point C %d \n", status);
        if (status == -1) {
            printf("Error in pcap_loop\n");
        }
    }
    while (status != -2);

    fprintf(stdout, "%u packet%s\n", packets_captured,
		PLURAL_SUFFIX(packets_captured));
}

int main()
{
    while(1)
    {
        dumper();
        // sleep(1);
    }
    return 0;
} 