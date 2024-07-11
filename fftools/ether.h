#ifndef ether_h
#define ether_h

const char *mac48_string(netdissect_options *ndo, const uint8_t *ep);

int ethertype_print(netdissect_options *ndo, short ether_type, const char *p, int length, int caplen,
		const struct lladdr_info *src, const struct lladdr_info *dst);

        