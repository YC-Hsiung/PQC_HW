#ifndef CHACHA20
#define CHACHA20
#include <stdint.h>
#define ROUNDS 20
void chacha20(uint32 *, uin32 *);
static uint32 load_littleendian(const unsigned char *);
static void store_littleendian(unsigned char *, uint32);
static int crypto_core_chacha20(unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *);
void crypto_stream_chacha20(unsigned char *, unsigned long long, const unsigned char *, const unsigned char *);
void QR(uint32 *, uint32 *, uint32 *, uint32 *);
#endif