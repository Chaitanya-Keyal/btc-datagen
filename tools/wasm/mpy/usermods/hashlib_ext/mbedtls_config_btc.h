/* Just what hashlib_ext.c calls: SHA-512, RIPEMD-160, HMAC through MD, and PBKDF2.
 * Plain C implementations; the ESP32's hardware SHA acceleration has no equivalent
 * here and produces the same digests. */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_RIPEMD160_C
#define MBEDTLS_PKCS5_C
