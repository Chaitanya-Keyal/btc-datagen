/* The library itself, one translation unit as the firmware builds it. The port
 * compiles with -Werror, and this pinned third-party source has a warning clang
 * flags (bitwise & on booleans in ecdsa_impl.h), so warnings stop here. */
#pragma clang diagnostic ignored "-Weverything"
#define HAVE_CONFIG_H 1
#include "../../../../../deps/esp-secp256k1/secp256k1-zkp/src/secp256k1.c"
