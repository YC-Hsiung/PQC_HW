#include "chacha20.h"
void chacha20(uint32 out[16], uint32 const in[16])
{
    int i;
    uint32 x[16];

    for (i = 0; i < 16; ++i)
        x[i] = in[i];
    for (i = 0; i < 20; i += 2)
    {
        QR(&x[0], &x[4], &x[8], &x[12]);
        QR(&x[1], &x[5], &x[9], &x[13]);
        QR(&x[2], &x[6], &x[10], &x[14]);
        QR(&x[3], &x[7], &x[11], &x[15]);
        QR(&x[0], &x[5], &x[10], &x[15]);
        QR(&x[1], &x[6], &x[11], &x[12]);
        QR(&x[2], &x[7], &x[8], &x[13]);
        QR(&x[3], &x[4], &x[9], &x[14]);
    }
    for (i = 0; i < 16; ++i)
        out[i] = x[i] + in[i];
}

static uint32 load_littleendian(const unsigned char *x)
{
    return (uint32)(x[0]) | (((uint32)(x[1])) << 8) | (((uint32)(x[2])) << 16) | (((uint32)(x[3])) << 24);
}

static void store_littleendian(unsigned char *x, uint32 u)
{
    x[0] = u;
    u >>= 8;
    x[1] = u;
    u >>= 8;
    x[2] = u;
    u >>= 8;
    x[3] = u;
}
static int crypto_core_chacha20(
    unsigned char *out,
    const unsigned char *in,
    const unsigned char *k,
    const unsigned char *c)
{
    uint32 x[16];
    uint32 o[16];
    for (int i = 0; i < 4; i++)
    {
        x[i] = o[i] = load_littleendian(c + i * 4);
    }
    for (int i = 4; i < 12; i++)
    {
        x[i] = o[i] = load_littleendian(k + (i - 4) * 4);
    }
    x[12] = o[12] = load_littleendian(in + 8);
    x[13] = o[13] = load_littleendian(in + 12);
    x[14] = o[14] = load_littleendian(in + 0);
    x[15] = o[15] = load_littleendian(in + 4);

    for (int i = 0; i < ROUNDS; i += 2)
    {
        QR(&x[0], &x[4], &x[8], &x[12]);
        QR(&x[1], &x[5], &x[9], &x[13]);
        QR(&x[2], &x[6], &x[10], &x[14]);
        QR(&x[3], &x[7], &x[11], &x[15]);
        QR(&x[0], &x[5], &x[10], &x[15]);
        QR(&x[1], &x[6], &x[11], &x[12]);
        QR(&x[2], &x[7], &x[8], &x[13]);
        QR(&x[3], &x[4], &x[9], &x[14]);
    }
    for (int i = 0; i < 16, i++)
    {
        store_littleendian(out + i * 4, x[i] + o[i]);
    }
    return 0;
}
void crypto_stream_chacha20(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k)
{
    unsigned char in[16];
    unsigned char block[64];
    unsigned char kcopy[32];
    unsigned long long i;
    unsigned int u;

    if (!clen)
        return;

    for (i = 0; i < 32; ++i)
        kcopy[i] = k[i];
    for (i = 0; i < 8; ++i)
        in[i] = n[i];
    for (i = 8; i < 16; ++i)
        in[i] = 0;

    while (clen >= 64)
    {
        unsigned char sigma[16] = "expand 32-byte k";
        crypto_core_chacha20(c, in, kcopy, sigma);

        u = 1;
        for (i = 8; i < 16; ++i)
        {
            u += (unsigned int)in[i];
            in[i] = u;
            u >>= 8;
        }

        clen -= 64;
        c += 64;
    }

    if (clen)
    {
        crypto_core_chacha20(block, in, kcopy, sigma);
        for (i = 0; i < clen; ++i)
            c[i] = block[i];
    }
    return;
}