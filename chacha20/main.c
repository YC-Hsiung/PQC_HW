#include "chacha20.h"

#define OUTLEN 1024

unsigned char out[OUTLEN];

unsigned char key[CHACHA20_KEYBYTES] = {
    0x57, 0x6c, 0x7c, 0x77, 0x6a, 0xc2, 0x93, 0xc6, 0x78, 0x3a, 0x4a, 0x48, 0xc9, 0x45, 0x20, 0x36,
    0x7d, 0xb3, 0xd4, 0x8c, 0x66, 0xa0, 0x52, 0xa8, 0xb2, 0xea, 0x09, 0xdc, 0x41, 0x43, 0xc5, 0x61};
unsigned char nonce[CHACHA20_NONCEBYTES] = {
    0xa8, 0xc8, 0x48, 0x1f, 0xf2, 0x6b, 0x13, 0x86};

int main(void)
{
    char outstr[128];
    uint64_t oldcount, newcount;

    hal_setup(CLOCK_BENCHMARK);

    hal_send_str("\n============ IGNORE OUTPUT BEFORE THIS LINE ============\n");

    oldcount = hal_get_time();
    crypto_stream_chacha20(out, OUTLEN, nonce, key);
    newcount = hal_get_time();

    sprintf(outstr, "\ncycles for %d bytes: %llu", OUTLEN, newcount - oldcount);

    hal_send_str(outstr);

    while (1)
        ;

    return 0;
}