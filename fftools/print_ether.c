#include "netdissect.h"

#define ETHER_HDRLEN 14

struct	ether_header {
	nd_mac48	ether_dhost;
	nd_mac48	ether_shost;
	nd_uint16_t	ether_length_type;
};


static int
ether_common_print(netdissect_options *ndo, const char *p, int length,
    int caplen,
    void (*print_switch_tag)(netdissect_options *ndo, const char *),
    int switch_tag_len,
    void (*print_encap_header)(netdissect_options *ndo, const char *),
    const char *encap_header_arg)
{
	const struct ether_header *ehp;
	int orig_length;
	int hdrlen;
	short length_type;
	int printed_length;
	int llc_hdrlen;
	struct lladdr_info src, dst;

	if (length < caplen) {
		ND_PRINT("[length %u < caplen %u]", length, caplen);
		nd_print_invalid(ndo);
		return length;
	}
	if (caplen < ETHER_HDRLEN + switch_tag_len) {
		nd_print_trunc(ndo);
		return caplen;
	}

	if (print_encap_header != NULL)
		(*print_encap_header)(ndo, encap_header_arg);

	orig_length = length;

	/*
	 * Get the source and destination addresses, skip past them,
	 * and print them if we're printing the link-layer header.
	 */
	ehp = (const struct ether_header *)p;
	src.addr = ehp->ether_shost;
	src.addr_string = mac48_string;
	dst.addr = ehp->ether_dhost;
	dst.addr_string = mac48_string;

	length -= 2*MAC48_LEN;
	caplen -= 2*MAC48_LEN;
	p += 2*MAC48_LEN;
	hdrlen = 2*MAC48_LEN;

	if (ndo->ndo_eflag)
		ether_addresses_print(ndo, src.addr, dst.addr);

	/*
	 * Print the switch tag, if we have one, and skip past it.
	 */
	if (print_switch_tag != NULL)
		(*print_switch_tag)(ndo, p);

	length -= switch_tag_len;
	caplen -= switch_tag_len;
	p += switch_tag_len;
	hdrlen += switch_tag_len;

	/*
	 * Get the length/type field, skip past it, and print it
	 * if we're printing the link-layer header.
	 */
recurse:
	length_type = GET_BE_U_2(p);

	length -= 2;
	caplen -= 2;
	p += 2;
	hdrlen += 2;

	/*
	 * Process 802.1AE MACsec headers.
	 */
	printed_length = 0;
	if (length_type == ETHERTYPE_MACSEC) {
		/*
		 * MACsec, aka IEEE 802.1AE-2006
		 * Print the header, and try to print the payload if it's not encrypted
		 */
		if (ndo->ndo_eflag) {
			ether_type_print(ndo, length_type);
			ND_PRINT(", length %u: ", orig_length);
			printed_length = 1;
		}

		int ret = macsec_print(ndo, &p, &length, &caplen, &hdrlen,
				       &src, &dst);

		if (ret == 0) {
			/* Payload is encrypted; print it as raw data. */
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
			return hdrlen;
		} else if (ret > 0) {
			/* Problem printing the header; just quit. */
			return ret;
		} else {
			/*
			 * Keep processing type/length fields.
			 */
			length_type = GET_BE_U_2(p);

			ND_ICHECK_U(caplen, <, 2);
			length -= 2;
			caplen -= 2;
			p += 2;
			hdrlen += 2;
		}
	}

	/*
	 * Process VLAN tag types.
	 */
	while (length_type == ETHERTYPE_8021Q  ||
		length_type == ETHERTYPE_8021Q9100 ||
		length_type == ETHERTYPE_8021Q9200 ||
		length_type == ETHERTYPE_8021QinQ) {
		/*
		 * It has a VLAN tag.
		 * Print VLAN information, and then go back and process
		 * the enclosed type field.
		 */
		if (caplen < 4) {
			ndo->ndo_protocol = "vlan";
			nd_print_trunc(ndo);
			return hdrlen + caplen;
		}
		if (length < 4) {
			ndo->ndo_protocol = "vlan";
			nd_print_trunc(ndo);
			return hdrlen + length;
		}
		if (ndo->ndo_eflag) {
			uint16_t tag = GET_BE_U_2(p);

			ether_type_print(ndo, length_type);
			if (!printed_length) {
				ND_PRINT(", length %u: ", orig_length);
				printed_length = 1;
			} else
				ND_PRINT(", ");
			ND_PRINT("%s, ", ieee8021q_tci_string(tag));
		}

		length_type = GET_BE_U_2(p + 2);
		p += 4;
		length -= 4;
		caplen -= 4;
		hdrlen += 4;
	}

	/*
	 * We now have the final length/type field.
	 */
	if (length_type <= MAX_ETHERNET_LENGTH_VAL) {
		/*
		 * It's a length field, containing the length of the
		 * remaining payload; use it as such, as long as
		 * it's not too large (bigger than the actual payload).
		 */
		if (length_type < length) {
			length = length_type;
			if (caplen > length)
				caplen = length;
		}

		/*
		 * Cut off the snapshot length to the end of the
		 * payload.
		 */
		if (!nd_push_snaplen(ndo, p, length)) {
			(*ndo->ndo_error)(ndo, S_ERR_ND_MEM_ALLOC,
				"%s: can't push snaplen on buffer stack", __func__);
		}

		if (ndo->ndo_eflag) {
			ND_PRINT("802.3");
			if (!printed_length)
				ND_PRINT(", length %u: ", length);
		}

		/*
		 * An LLC header follows the length.  Print that and
		 * higher layers.
		 */
		llc_hdrlen = llc_print(ndo, p, length, caplen, &src, &dst);
		if (llc_hdrlen < 0) {
			/* packet type not known, print raw packet */
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
			llc_hdrlen = -llc_hdrlen;
		}
		hdrlen += llc_hdrlen;
		nd_pop_packet_info(ndo);
	} else if (length_type == ETHERTYPE_JUMBO) {
		/*
		 * It's a type field, with the type for Alteon jumbo frames.
		 * See
		 *
		 *	https://tools.ietf.org/html/draft-ietf-isis-ext-eth-01
		 *
		 * which indicates that, following the type field,
		 * there's an LLC header and payload.
		 */
		/* Try to print the LLC-layer header & higher layers */
		llc_hdrlen = llc_print(ndo, p, length, caplen, &src, &dst);
		if (llc_hdrlen < 0) {
			/* packet type not known, print raw packet */
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
			llc_hdrlen = -llc_hdrlen;
		}
		hdrlen += llc_hdrlen;
	} else if (length_type == ETHERTYPE_ARISTA) {
		if (caplen < 2) {
			ND_PRINT("[|arista]");
			return hdrlen + caplen;
		}
		if (length < 2) {
			ND_PRINT("[|arista]");
			return hdrlen + length;
		}
		ether_type_print(ndo, length_type);
		ND_PRINT(", length %u: ", orig_length);
		int bytesConsumed = arista_ethertype_print(ndo, p, length);
		if (bytesConsumed > 0) {
			p += bytesConsumed;
			length -= bytesConsumed;
			caplen -= bytesConsumed;
			hdrlen += bytesConsumed;
			goto recurse;
		} else {
			/* subtype/version not known, print raw packet */
			if (!ndo->ndo_eflag && length_type > MAX_ETHERNET_LENGTH_VAL) {
				ether_addresses_print(ndo, src.addr, dst.addr);
				ether_type_print(ndo, length_type);
				ND_PRINT(", length %u: ", orig_length);
			}
			 if (!ndo->ndo_suppress_default_print)
				 ND_DEFAULTPRINT(p, caplen);
		}
	} else {
		/*
		 * It's a type field with some other value.
		 */
		if (ndo->ndo_eflag) {
			ether_type_print(ndo, length_type);
			if (!printed_length)
				ND_PRINT(", length %u: ", orig_length);
			else
				ND_PRINT(", ");
		}
		if (ethertype_print(ndo, length_type, p, length, caplen, &src, &dst) == 0) {
			/* type not known, print raw packet */
			if (!ndo->ndo_eflag) {
				/*
				 * We didn't print the full link-layer
				 * header, as -e wasn't specified, so
				 * print only the source and destination
				 * MAC addresses and the final Ethernet
				 * type.
				 */
				ether_addresses_print(ndo, src.addr, dst.addr);
				ether_type_print(ndo, length_type);
				ND_PRINT(", length %u: ", orig_length);
			}

			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
		}
	}
invalid:
	return hdrlen;
}

int
ether_print(netdissect_options *ndo,
	    const char *p, int length, int caplen,
	    void (*print_encap_header)(netdissect_options *ndo, const char *),
	    const char *encap_header_arg)
{
	ndo->ndo_protocol = "ether";
	return ether_common_print(ndo, p, length, caplen, NULL, 0,
				  print_encap_header, encap_header_arg);
}

void
ether_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
	       const char *p)
{
	ndo->ndo_protocol = "ether";
	ndo->ndo_ll_hdr_len +=
		ether_print(ndo, p, h->len, h->caplen, NULL, NULL);
}