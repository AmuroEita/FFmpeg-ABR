#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netdissect.h"
#include "utils.h"

int
nd_init(char *errbuf, size_t errbuf_size)
{
	/*
	 * Clears the error buffer, and uses it so we don't get
	 * "unused argument" warnings at compile time.
	 */
	strlcpy(errbuf, "", errbuf_size);
	return (0);
}

/* Free chunks in allocation linked list from last to first */
void
nd_free_all(netdissect_options *ndo)
{
	nd_mem_chunk_t *current, *previous;
	current = ndo->ndo_last_mem_p;
	while (current != NULL) {
		previous = current->prev_mem_p;
		free(current);
		current = previous;
	}
	ndo->ndo_last_mem_p = NULL;
}

void
nd_pop_packet_info(netdissect_options *ndo)
{
	struct netdissect_saved_packet_info *ndspi;

	ndspi = ndo->ndo_packet_info_stack;
	ndo->ndo_packetp = ndspi->ndspi_packetp;
	ndo->ndo_snapend = ndspi->ndspi_snapend;
	ndo->ndo_packet_info_stack = ndspi->ndspi_prev;

	free(ndspi->ndspi_buffer);
	free(ndspi);
}

void
nd_pop_all_packet_info(netdissect_options *ndo)
{
	while (ndo->ndo_packet_info_stack != NULL)
		nd_pop_packet_info(ndo);
}

int
nd_push_snaplen(netdissect_options *ndo, const char *bp, const int newlen)
{
	struct netdissect_saved_packet_info *ndspi;
	int snaplen_remaining;

	ndspi = (struct netdissect_saved_packet_info *)malloc(sizeof(struct netdissect_saved_packet_info));
	if (ndspi == NULL)
		return (0);	/* fail */
	ndspi->ndspi_buffer = NULL;	/* no new buffer */
	ndspi->ndspi_packetp = ndo->ndo_packetp;
	ndspi->ndspi_snapend = ndo->ndo_snapend;
	ndspi->ndspi_prev = ndo->ndo_packet_info_stack;

	/*
	 * Push the saved previous data onto the stack.
	 */
	ndo->ndo_packet_info_stack = ndspi;

	/*
	 * Find out how many bytes remain after the current snapend.
	 *
	 * We're restricted to packets with at most UINT_MAX bytes;
	 * cast the result to u_int, so that we don't get truncation
	 * warnings on LP64 and LLP64 platforms.  (ptrdiff_t is
	 * signed and we want an unsigned difference; the pointer
	 * should at most be equal to snapend, and must *never*
	 * be past snapend.)
	 */
	snaplen_remaining = (int)(ndo->ndo_snapend - bp);

	/*
	 * If the new snapend is smaller than the one calculated
	 * above, set the snapend to that value, otherwise leave
	 * it unchanged.
	 */
	if (newlen <= snaplen_remaining) {
		/* Snapend isn't past the previous snapend */
		ndo->ndo_snapend = bp + newlen;
	}

	return (1);	/* success */
}

struct hnamemem *
newhnamemem(netdissect_options *ndo)
{
	struct hnamemem *p;
	static struct hnamemem *ptr = NULL;
	static int num = 0;

	if (num  == 0) {
		num = 64;
		ptr = (struct hnamemem *)calloc(num, sizeof (*ptr));
	}
	--num;
	p = ptr++;
	return (p);
}

static const char *
intoa(uint32_t addr)
{
	char *cp;
	int byte;
	int n;
	static char buf[sizeof(".xxx.xxx.xxx.xxx")];

	addr = ntohl(addr);
	cp = buf + sizeof(buf);
	*--cp = '\0';

	n = 4;
	do {
		byte = addr & 0xff;
		*--cp = (char)(byte % 10) + '0';
		byte /= 10;
		if (byte > 0) {
			*--cp = (char)(byte % 10) + '0';
			byte /= 10;
			if (byte > 0)
				*--cp = (char)byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	} while (--n > 0);

	return cp + 1;
}

const char *
ipaddr_string(netdissect_options *ndo, const char *ap)
{
	struct hostent *hp;
	uint32_t addr;
	struct hnamemem *p;

	memcpy(&addr, ap, sizeof(addr));
	p = &hnametable[addr & (HASHNAMESIZE-1)];
	for (; p->nxt; p = p->nxt) {
		if (p->addr == addr)
			return (p->name);
	}
	p->addr = addr;
	p->nxt = newhnamemem(ndo);

	p->name = strdup(intoa(addr));
	return (p->name);
}

void
nd_trunc_longjmp(netdissect_options *ndo)
{
	longjmp(ndo->ndo_early_end, 1);
}