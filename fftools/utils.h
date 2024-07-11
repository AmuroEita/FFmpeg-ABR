#ifndef utils_h
#define utils_h

#include <stddef.h>

#define IN6ADDRSZ   16 

#define INT16SZ     2  

#define INET_ADDRSTRLEN 16

struct tok {
	int v;		/* value */
	const char *s;		/* string */
};

size_t strlcpy(char *, const char *, size_t);

const char * tok2str(const struct tok *, const char *, const int);

char * bittok2str(const struct tok *, const char *, const int);

const char *netdb_protoname (const uint8_t);

char *bittok2str_nosep(const struct tok *, const char *, const int);

const char *addrtostr6(const void *src, char *dst, size_t size);

const char *addrtostr (const void *src, char *dst, size_t size);



#endif