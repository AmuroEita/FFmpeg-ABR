#include <netinet/in.h>
#include <time.h>
#include <regex.h>
#include <string.h>

#include "netdissect.h"

#define MAX_TOKEN 128
#define RESP_CODE_SECOND_TOKEN 0x00000001

#define ND_ISASCII(c) (!((c) & 0x80)) /* value is an ASCII code point */
#define ND_ASCII_ISPRINT(c) ((c) >= 0x20 && (c) <= 0x7E)
#define ND_ASCII_ISDIGIT(c) ((c) >= '0' && (c) <= '9')
#define ND_ASCII_TOUPPER(c) (((c) >= 'a' && (c) <= 'z') ? (c) - 'a' + 'A' : (c))

#define DASH_SEG_SUFFIX ".m4s"
#define DASH_AUDIO_DIR "audio"
#define DASH_VIDEO_DIR "video"

extern const char *init_file;

extern FILE *net_stat_fp;

extern int tcp_packets_cnt;
extern uint16_t total_win;

extern float throughtout;
extern float download_time;

/*
 * Includes WebDAV requests.
 */
static const char *httpcmds[] = {
	"GET",
	"PUT",
	"COPY",
	"HEAD",
	"LOCK",
	"MOVE",
	"POLL",
	"POST",
	"BCOPY",
	"BMOVE",
	"MKCOL",
	"TRACE",
	"LABEL",
	"MERGE",
	"DELETE",
	"SEARCH",
	"UNLOCK",
	"REPORT",
	"UPDATE",
	"NOTIFY",
	"BDELETE",
	"CONNECT",
	"OPTIONS",
	"CHECKIN",
	"PROPFIND",
	"CHECKOUT",
	"CCM_POST",
	"SUBSCRIBE",
	"PROPPATCH",
	"BPROPFIND",
	"BPROPPATCH",
	"UNCHECKOUT",
	"MKACTIVITY",
	"MKWORKSPACE",
	"UNSUBSCRIBE",
	"RPC_CONNECT",
	"VERSION-CONTROL",
	"BASELINE-CONTROL",
	NULL};

static const unsigned char charmap[] = {
	0x00,
	0x01,
	0x02,
	0x03,
	0x04,
	0x05,
	0x06,
	0x07,
	0x08,
	0x09,
	0x0a,
	0x0b,
	0x0c,
	0x0d,
	0x0e,
	0x0f,
	0x10,
	0x11,
	0x12,
	0x13,
	0x14,
	0x15,
	0x16,
	0x17,
	0x18,
	0x19,
	0x1a,
	0x1b,
	0x1c,
	0x1d,
	0x1e,
	0x1f,
	0x20,
	0x21,
	0x22,
	0x23,
	0x24,
	0x25,
	0x26,
	0x27,
	0x28,
	0x29,
	0x2a,
	0x2b,
	0x2c,
	0x2d,
	0x2e,
	0x2f,
	0x30,
	0x31,
	0x32,
	0x33,
	0x34,
	0x35,
	0x36,
	0x37,
	0x38,
	0x39,
	0x3a,
	0x3b,
	0x3c,
	0x3d,
	0x3e,
	0x3f,
	0x40,
	0x61,
	0x62,
	0x63,
	0x64,
	0x65,
	0x66,
	0x67,
	0x68,
	0x69,
	0x6a,
	0x6b,
	0x6c,
	0x6d,
	0x6e,
	0x6f,
	0x70,
	0x71,
	0x72,
	0x73,
	0x74,
	0x75,
	0x76,
	0x77,
	0x78,
	0x79,
	0x7a,
	0x5b,
	0x5c,
	0x5d,
	0x5e,
	0x5f,
	0x60,
	0x61,
	0x62,
	0x63,
	0x64,
	0x65,
	0x66,
	0x67,
	0x68,
	0x69,
	0x6a,
	0x6b,
	0x6c,
	0x6d,
	0x6e,
	0x6f,
	0x70,
	0x71,
	0x72,
	0x73,
	0x74,
	0x75,
	0x76,
	0x77,
	0x78,
	0x79,
	0x7a,
	0x7b,
	0x7c,
	0x7d,
	0x7e,
	0x7f,
	0x80,
	0x81,
	0x82,
	0x83,
	0x84,
	0x85,
	0x86,
	0x87,
	0x88,
	0x89,
	0x8a,
	0x8b,
	0x8c,
	0x8d,
	0x8e,
	0x8f,
	0x90,
	0x91,
	0x92,
	0x93,
	0x94,
	0x95,
	0x96,
	0x97,
	0x98,
	0x99,
	0x9a,
	0x9b,
	0x9c,
	0x9d,
	0x9e,
	0x9f,
	0xa0,
	0xa1,
	0xa2,
	0xa3,
	0xa4,
	0xa5,
	0xa6,
	0xa7,
	0xa8,
	0xa9,
	0xaa,
	0xab,
	0xac,
	0xad,
	0xae,
	0xaf,
	0xb0,
	0xb1,
	0xb2,
	0xb3,
	0xb4,
	0xb5,
	0xb6,
	0xb7,
	0xb8,
	0xb9,
	0xba,
	0xbb,
	0xbc,
	0xbd,
	0xbe,
	0xbf,
	0xc0,
	0xc1,
	0xc2,
	0xc3,
	0xc4,
	0xc5,
	0xc6,
	0xc7,
	0xc8,
	0xc9,
	0xca,
	0xcb,
	0xcc,
	0xcd,
	0xce,
	0xcf,
	0xd0,
	0xd1,
	0xd2,
	0xd3,
	0xd4,
	0xd5,
	0xd6,
	0xd7,
	0xd8,
	0xd9,
	0xda,
	0xdb,
	0xdc,
	0xdd,
	0xde,
	0xdf,
	0xe0,
	0xe1,
	0xe2,
	0xe3,
	0xe4,
	0xe5,
	0xe6,
	0xe7,
	0xe8,
	0xe9,
	0xea,
	0xeb,
	0xec,
	0xed,
	0xee,
	0xef,
	0xf0,
	0xf1,
	0xf2,
	0xf3,
	0xf4,
	0xf5,
	0xf6,
	0xf7,
	0xf8,
	0xf9,
	0xfa,
	0xfb,
	0xfc,
	0xfd,
	0xfe,
	0xff,
};

static void nd_print_protocol_caps(netdissect_options *ndo)
{
	const char *p;
	for (p = ndo->ndo_protocol; *p != '\0'; p++)
		ND_PRINT("%c", ND_ASCII_TOUPPER(*p));
}

static int ascii_strcasecmp(const char *s1, const char *s2)
{
	const unsigned char *cm = charmap,
						*us1 = (const unsigned char *)s1,
						*us2 = (const unsigned char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return (0);
	return (cm[*us1] - cm[*--us2]);
}

static int extract_between(const char *source, char *result, size_t result_size)
{
	regex_t regex;
	regmatch_t matches[2];
	int ret;

	const char *pattern = "GET .*?.m4s HTTP";
	ret = regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE);
	if (ret) {
	    fprintf(stderr, "Could not compile regex\n");
	    return -1;
	}

	ret = regexec(&regex, source, 2, matches, 0);
	if (!ret) {
	    int start = matches[0].rm_so;
	    int end = matches[0].rm_eo;
	    if (end - start + 1 > result_size) {
	        fprintf(stderr, "Result buffer is too small\n");
	        regfree(&regex);
	        return -1;
	    }
	    strncpy(result, source + start, end - start);
	    result[end - start] = '\0';
	    regfree(&regex);
	    return 0;
	} else if (ret == REG_NOMATCH) {
	    fprintf(stderr, "No match found\n");
	} else {
	    fprintf(stderr, "Regex match failed\n");
	}
	regfree(&regex);
	return -1;
}

static void extractSubString(const char *source, char *result, size_t result_size) {
    size_t source_length = strlen(source);
    size_t start_index = 4; // 第五个字符的索引（从0开始计数）
    size_t end_index = source_length - 6; // 倒数第六个字符的索引

    // 确保起始和结束索引在字符串范围内
    if (start_index >= source_length || end_index < start_index) {
        fprintf(stderr, "Invalid indices for the source string\n");
        return;
    }

    // 计算子字符串的长度
    size_t sub_length = end_index - start_index + 1;

    // 确保结果缓冲区足够大
    if (sub_length + 1 > result_size) {
        fprintf(stderr, "Result buffer is too small\n");
        return;
    }

    // 复制子字符串
    strncpy(result, source + start_index, sub_length);
    result[sub_length] = '\0'; // 确保子字符串以空字符结尾
}

static int ascii_strstr(const char *s1, const char *s2)
{
	const unsigned char *cm = charmap,
						*us1 = (const unsigned char *)s1,
						*us2 = (const unsigned char *)s2;

	while (*us1)
	{
		if (cm[*us1] == cm[*us2])
		{
			const unsigned char *tmp_s1 = us1 + 1;
			const unsigned char *tmp_s2 = us2 + 1;
			while (*tmp_s1 && *tmp_s1 == *tmp_s2)
			{
				tmp_s1++;
				tmp_s2++;
			}

			if (*tmp_s2 == '\0')
			{
				return 1;
			}
		}
		us1++;
	}
	return 0;
}

static int fetch_token(netdissect_options *ndo, const char *pptr, int idx, int len,
					   char *tbuf, size_t tbuflen)
{
	size_t toklen = 0;
	char c;

	for (; idx < len; idx++)
	{
		if (!ND_TTEST_1(pptr + idx))
		{
			/* ran past end of captured data */
			return (0);
		}
		c = GET_U_1(pptr + idx);
		if (!ND_ISASCII(c))
		{
			/* not an ASCII character */
			return (0);
		}
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
		{
			/* end of token */
			break;
		}
		if (!ND_ASCII_ISPRINT(c))
		{
			/* not part of a command token or response code */
			return (0);
		}
		if (toklen + 2 > tbuflen)
		{
			/* no room for this character and terminating '\0' */
			return (0);
		}
		tbuf[toklen] = c;
		toklen++;
	}
	if (toklen == 0)
	{
		/* no token */
		return (0);
	}
	tbuf[toklen] = '\0';

	/*
	 * Skip past any white space after the token, until we see
	 * an end-of-line (CR or LF).
	 */
	for (; idx < len; idx++)
	{
		if (!ND_TTEST_1(pptr + idx))
		{
			/* ran past end of captured data */
			break;
		}
		c = GET_U_1(pptr + idx);
		if (c == '\r' || c == '\n')
		{
			/* end of line */
			break;
		}
		if (!ND_ASCII_ISPRINT(c))
		{
			/* not a printable ASCII character */
			break;
		}
		if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
		{
			/* beginning of next token */
			break;
		}
	}
	return (idx);
}

static int print_txt_line(netdissect_options *ndo, const char *prefix,
						  const char *pptr, int idx, int len)
{
	int startidx;
	int linelen;
	char c;

	startidx = idx;
	while (idx < len)
	{
		c = GET_U_1(pptr + idx);
		if (c == '\n')
		{
			/*
			 * LF without CR; end of line.
			 * Skip the LF and print the line, with the
			 * exception of the LF.
			 */
			linelen = idx - startidx;
			idx++;
			goto print;
		}
		else if (c == '\r')
		{
			/* CR - any LF? */
			if ((idx + 1) >= len)
			{
				/* not in this packet */
				return (0);
			}
			if (GET_U_1(pptr + idx + 1) == '\n')
			{
				/*
				 * CR-LF; end of line.
				 * Skip the CR-LF and print the line, with
				 * the exception of the CR-LF.
				 */
				linelen = idx - startidx;
				idx += 2;
				goto print;
			}

			/*
			 * CR followed by something else; treat this
			 * as if it were binary data, and don't print
			 * it.
			 */
			return (0);
		}
		else if (!ND_ASCII_ISPRINT(c) && c != '\t')
		{
			/*
			 * Not a printable ASCII character and not a tab;
			 * treat this as if it were binary data, and
			 * don't print it.
			 */
			return (0);
		}
		idx++;
	}

	/*
	 * All printable ASCII, but no line ending after that point
	 * in the buffer.
	 */
	linelen = idx - startidx;
	ND_PRINT("%s%.*s", prefix, (int)linelen, pptr + startidx);
	return (0);

print:

	if (init_file != NULL && ascii_strstr(pptr + startidx, (const char *)DASH_SEG_SUFFIX) && !ascii_strstr(pptr + startidx, init_file))
	{

		uint16_t ave_win = 0;
		if (total_win != 0 && tcp_packets_cnt != 0)
			ave_win = total_win / (uint16_t)tcp_packets_cnt;

		int seg_type = 1;
		if (ascii_strstr(pptr + startidx, (const char *)DASH_VIDEO_DIR))
			seg_type = 0;

		time_t now = time(NULL);

		char tmp[256];
		char path[50];

		if (extract_between(pptr + startidx, tmp, sizeof(tmp)) == 0)
		{
			extractSubString(tmp, path, sizeof(path));
		}

		fprintf(net_stat_fp, "%ld %u %d %d %s \n", now, ave_win, tcp_packets_cnt, seg_type, path);
		fflush(net_stat_fp);
	}

	tcp_packets_cnt = 0;
	total_win = 0;

	return (idx);
}

/* Assign needed before calling txtproto_print(): ndo->ndo_protocol = "proto" */
static void txtproto_print(netdissect_options *ndo, const char *pptr, int len,
						   const char **cmds, int flags)
{
	int idx, eol;
	char token[MAX_TOKEN + 1];
	const char *cmd;
	int print_this = 0;

	char *dig[4];

	if (cmds != NULL)
	{
		/*
		 * This protocol has more than just request and
		 * response lines; see whether this looks like a
		 * request or response and, if so, print it and,
		 * in verbose mode, print everything after it.
		 *
		 * This is for HTTP-like protocols, where we
		 * want to print requests and responses, but
		 * don't want to print continuations of request
		 * or response bodies in packets that don't
		 * contain the request or response line.
		 */
		idx = fetch_token(ndo, pptr, 0, len, token, sizeof(token));
		if (idx != 0)
		{
			/* Is this a valid request name? */
			while ((cmd = *cmds++) != NULL)
			{
				if (ascii_strcasecmp((const char *)token, cmd) == 0)
				{
					/* Yes. */
					print_this = 1;
					break;
				}
			}

			/*
			 * No - is this a valid response code (3 digits)?
			 *
			 * Is this token the response code, or is the next
			 * token the response code?
			 */
			if (flags & RESP_CODE_SECOND_TOKEN)
			{
				/*
				 * Next token - get it.
				 */
				idx = fetch_token(ndo, pptr, idx, len, token,
								  sizeof(token));
			}
			if (idx != 0)
			{
				if (ND_ASCII_ISDIGIT(token[0]) && ND_ASCII_ISDIGIT(token[1]) &&
					ND_ASCII_ISDIGIT(token[2]) && token[3] == '\0')
				{
					/* Yes. */

					strcpy(dig, token[0]);
					strcat(dig, token[1]);
					strcat(dig, token[2]);

					print_this = 1;
				}
			}
		}
	}
	else
	{
		/*
		 * Either:
		 *
		 * 1) This protocol has only request and response lines
		 *    (e.g., FTP, where all the data goes over a different
		 *    connection); assume the payload is a request or
		 *    response.
		 *
		 * or
		 *
		 * 2) This protocol is just text, so that we should
		 *    always, at minimum, print the first line and,
		 *    in verbose mode, print all lines.
		 */
		print_this = 1;
	}

	nd_print_protocol_caps(ndo);

	if (print_this)
	{
		/*
		 * In non-verbose mode, just print the protocol, followed
		 * by the first line.
		 *
		 * In verbose mode, print lines as text until we run out
		 * of characters or see something that's not a
		 * printable-ASCII line.
		 */

		ND_PRINT("\n\n RRRRRR : %s ", dig);

		if (ndo->ndo_vflag)
		{
			/*
			 * We're going to print all the text lines in the
			 * request or response; just print the length
			 * on the first line of the output.
			 */
			ND_PRINT(", length: %u ", len);
			for (idx = 0;
				 idx < len && (eol = print_txt_line(ndo, "\n\t", pptr, idx, len)) != 0;
				 idx = eol)
				;
		}
		else
		{
			/*
			 * Just print the first text line.
			 */
			print_txt_line(ndo, ": ", pptr, 0, len);
		}
	}
}

void http_print(netdissect_options *ndo, const char *pptr, int len)
{
	ndo->ndo_protocol = "http";

	txtproto_print(ndo, pptr, len, httpcmds, RESP_CODE_SECOND_TOKEN);
}
