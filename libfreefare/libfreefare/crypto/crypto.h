#ifndef LIBFREEFARE_CRYPTO_H
#define LIBFREEFARE_CRYPTO_H

#include <inttypes.h>

#ifdef USE_POLARSSL
#  include <polarssl/des.h>
#  include <polarssl/aes.h>
#else
// Using OpenSSL
#  include <openssl/des.h>
#  include <openssl/aes.h>
#endif


#ifdef __cplusplus
    extern "C" {
#endif // __cplusplus

    int crypto_get_random_bytes(uint8_t *buf, unsigned len);
    int crypto_get_des_random_key(uint8_t* key, unsigned keySize);

#ifdef __cplusplus
    }
#endif // __cplusplus



#endif // LIBFREEFARE_CRYPTO_H
