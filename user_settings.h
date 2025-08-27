#ifndef CUSTOM_USER_SETTINGS_H
#define CUSTOM_USER_SETTINGS_H

#define WOLFSSL_OPTIONS_H
#define WOLFSSL_USER_IO
#define WOLFSSL_USER_MUTEX
#define WOLFSSL_USER_LOG
#define WOLFSSL_TLS13
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_DTLS_CID
#define WOLFSSL_NO_TLS12
#define WOLFSSL_NO_SOCK
#define WOLFSSL_NO_GETPID
#define WOLFSSL_NO_MALLOC
#define WOLFSSL_ALWAYS_VERIFY_CB
#define WOLF_CRYPTO_CB
#define NO_WOLFSSL_SERVER
#define NO_FILESYSTEM
#define NO_STDIO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define NO_DEV_URANDOM
#define NO_DEV_RANDOM
#define NO_OLD_TLS
#define NO_WRITEV
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_RSA
#define HAVE_RPK
#define SINGLE_THREADED
#define NO_ASN_TIME
#define NO_TIMEVAL
#define STRING_USER
#define CTYPE_USER
#undef HAVE_ERRNO_H

#include <string.h>
#include <stdio.h>

#define USE_WOLF_STRSEP
#define XSTRSEP(s1,d)     wc_strsep((s1),(d))

#define USE_WOLF_STRTOK
#define XSTRTOK(s1,d,ptr) wc_strtok((s1),(d),(ptr))

#define USE_WOLF_STRNSTR
#define XSTRNSTR(s1,s2,n) mystrnstr((s1),(s2),(n))

int tolower(int ch);
void _wolfssl_log(const char *);

#define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
#define XMEMSET(b,c,l)    memset((b),(c),(l))
#define XMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
#define XMEMMOVE(d,s,l)   memmove((d),(s),(l))

#define XSTRLEN(s1)       strlen((s1))
#define XSTRNCPY(s1,s2,n) strncpy((s1),(s2),(n))
#define XSTRSTR(s1,s2)    strstr((s1),(s2))

#define XSTRNCMP(s1,s2,n)     strncmp((s1),(s2),(n))
#define XSTRCMP(s1,s2)        strcmp((s1),(s2))
#define XSTRCAT(s1,s2,n)      strcat((s1),(s2),(n))
#define XSTRNCAT(s1,s2,n)     strncat((s1),(s2),(n))
#define XSTRCASECMP(s1,s2)    strcmp((s1),(s2))
#define XSTRNCASECMP(s1,s2,n) strncasecmp((s1),(s2),(n))

#define XSNPRINTF snprintf

#define XTOLOWER(c)      tolower((c))

#define WOLFSSL_USER_LOG(m) _wolfssl_log(m)

#endif