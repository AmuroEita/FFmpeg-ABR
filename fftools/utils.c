#include <string.h>

#include "utils.h"

#define TOKBUFSIZE 128

size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

static const char *
tok2strbuf(const struct tok *lp, const char *fmt,
	   const int v, char *buf, const size_t bufsize)
{
	if (lp != NULL) {
		while (lp->s != NULL) {
			if (lp->v == v)
				return (lp->s);
			++lp;
		}
	}
	if (fmt == NULL)
		fmt = "#%d";

	(void)snprintf(buf, bufsize, fmt, v);
	return (const char *)buf;
}

const char *
tok2str(const struct tok *lp, const char *fmt, const int v)
{
	static char buf[4][TOKBUFSIZE];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}

static char *
bittok2str_internal(const struct tok *lp, const char *fmt,
		    const int v, const char *sep)
{
        static char buf[1024+1]; /* our string buffer */
        char *bufp = buf;
        size_t space_left = sizeof(buf), string_size;
        const char * sepstr = "";

        while (lp != NULL && lp->s != NULL) {
            if (lp->v && (v & lp->v) == lp->v) {
                /* ok we have found something */
                if (space_left <= 1)
                    return (buf); /* only enough room left for NUL, if that */
                string_size = strlcpy(bufp, sepstr, space_left);
                if (string_size >= space_left)
                    return (buf);    /* we ran out of room */
                bufp += string_size;
                space_left -= string_size;
                if (space_left <= 1)
                    return (buf); /* only enough room left for NUL, if that */
                string_size = strlcpy(bufp, lp->s, space_left);
                if (string_size >= space_left)
                    return (buf);    /* we ran out of room */
                bufp += string_size;
                space_left -= string_size;
                sepstr = sep;
            }
            lp++;
        }

        if (bufp == buf)
            /* bummer - lets print the "unknown" message as advised in the fmt string if we got one */
            (void)snprintf(buf, sizeof(buf), fmt == NULL ? "#%08x" : fmt, v);
        return (buf);
}

char *
bittok2str(const struct tok *lp, const char *fmt, const int v)
{
    return (bittok2str_internal(lp, fmt, v, ", "));
}
