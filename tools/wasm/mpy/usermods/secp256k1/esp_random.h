/* Stand-in for ESP-IDF's hardware RNG. modsecp256k1.c uses it only to seed
 * secp256k1_context_randomize, which blinds the arithmetic against side channels and
 * never changes a signature. Emscripten backs getentropy() with
 * crypto.getRandomValues(). */
#pragma once
#include <stddef.h>
#include <unistd.h>

static inline void esp_fill_random(void *buf, size_t len) { getentropy(buf, len); }
