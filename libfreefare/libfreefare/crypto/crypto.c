#include "crypto.h"
#include <assert.h>

#include <stdio.h>

#ifdef USE_POLARSSL
#  include "polarssl/havege.h"
#else
#  include <openssl/rand.h>
#endif

int crypto_get_random_bytes(uint8_t* buf, unsigned len)
{
    assert(buf && len);
#define HAVE_TRNG
#if defined(HAVE_TRNG)
    uint32_t true_random(void);
    for (unsigned i = 0; i < len; )
    {
        uint32_t rnd = true_random();
        for (unsigned j = 0; i < len && j < 4; ++i, ++j, ++buf)
        {
            *buf = rnd & 0xFF;
            rnd >>= 8;
        }
    }
    return 1;
#elif defined(USE_POLARSSL)
    havege_state hs;
    havege_init( &hs );
    int res = havege_random(&hs, buf, len);
    assert(res == 0);

    return 1;
#else
    return RAND_bytes(buf, len);
#endif
}

#ifdef USE_POLARSSL
static int crypto_polarssl_get_des_random_key(uint8_t* key, unsigned len)
{
    assert(len == DES_KEY_SIZE);

    do
    {
        if (crypto_get_random_bytes(key, len) != 1)
            return 0;

    } while (des_key_check_weak(key));

    des_key_set_parity(key); // Set key parity to odd
    return 1;
}
#endif

int crypto_get_des_random_key(uint8_t* key, unsigned keySize)
{
    assert(key && keySize);

#ifdef USE_POLARSSL
    return crypto_polarssl_get_des_random_key(key, keySize);
#else
    return DES_random_key ((DES_cblock*)key);
#endif
}
