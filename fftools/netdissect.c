#include <stdio.h>
#include <stdlib.h>

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