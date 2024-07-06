#ifndef utils_h
#define utils_h

struct tok {
	int v;		/* value */
	const char *s;		/* string */
};

size_t strlcpy(char *, const char *, size_t);

const char * tok2str(const struct tok *, const char *, const int);

char * bittok2str(const struct tok *, const char *, const int);

#endif