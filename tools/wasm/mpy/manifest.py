# Frozen into the fresh-key module. Paths are relative to this file.
#
# The firmware's hashlib.py and hmac.py shims route embit's SHA-512, PBKDF2,
# HMAC-SHA512, and RIPEMD-160 to the native `_hashlib_ext` module, as on the ESP32.
module("hashlib.py", base_path="../../../deps/seedsigner-micropython-builder/deps/third-party")
module("hmac.py", base_path="../../../deps/seedsigner-micropython-builder/deps/third-party")
# Upstream embit 0.8.0.
package("embit", base_path="../../../deps/embit/src")
# The session builder the page calls.
module("freshkey.py")
