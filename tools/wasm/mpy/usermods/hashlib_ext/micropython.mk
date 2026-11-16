# SHA-512, PBKDF2-HMAC-SHA512, HMAC-SHA512, and RIPEMD-160 for MicroPython: the ESP32
# firmware's `_hashlib_ext` module over the mbedtls ESP-IDF 5.5.1 ships, built here
# with only the four primitives it calls. BTC_DEPS is passed by build_mpy.sh.
FW_DIR := $(BTC_DEPS)/seedsigner-micropython-builder
SRC_USERMOD_C += $(FW_DIR)/bindings/modhashlibext.c
SRC_USERMOD_LIB_C += $(FW_DIR)/deps/esp-hashlib-ext/hashlib_ext.c \
  $(USERMOD_DIR)/mbedtls_md.c $(USERMOD_DIR)/mbedtls_sha512.c \
  $(USERMOD_DIR)/mbedtls_ripemd160.c $(USERMOD_DIR)/mbedtls_pkcs5.c \
  $(USERMOD_DIR)/mbedtls_platform_util.c
CFLAGS_USERMOD += -I$(USERMOD_DIR) -I$(FW_DIR)/deps/esp-hashlib-ext \
  -I$(BTC_DEPS)/mbedtls/include -DMBEDTLS_CONFIG_FILE='"mbedtls_config_btc.h"'
