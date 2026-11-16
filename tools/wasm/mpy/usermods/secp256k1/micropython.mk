# libsecp256k1 for MicroPython: the ESP32 firmware's binding (the `secp256k1` module
# embit imports on MicroPython) over secp256k1-zkp @ d9560e0, with the firmware
# component's own config and precomputed table. BTC_DEPS is passed by build_mpy.sh.
SECP_DIR := $(BTC_DEPS)/esp-secp256k1
SRC_USERMOD_C += $(SECP_DIR)/mpy/modsecp256k1.c
SRC_USERMOD_LIB_C += $(USERMOD_DIR)/secp256k1_lib.c
CFLAGS_USERMOD += -I$(USERMOD_DIR) -I$(SECP_DIR)/secp256k1-zkp/include \
  -I$(SECP_DIR)/config -I$(SECP_DIR)/generated -I$(SECP_DIR)/secp256k1-zkp
