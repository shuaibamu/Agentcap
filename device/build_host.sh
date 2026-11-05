#!/bin/sh
# Build the device verifiers as a host shared library (used by tests and attack experiments).
set -e
cd "$(dirname "$0")"; E=../third_party
${CC:-gcc} -O2 -shared -fPIC -DWITH_ED25519 -DWITH_P256 -DWITH_CCM \
  -I$E/Monocypher/src -I$E/Monocypher/src/optional -I$E/micro-ecc -I$E/tiny-AES-c \
  -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256k1=0 \
  -o libverif.so verif.c sha256.c aesccm.c $E/tiny-AES-c/aes.c \
  $E/Monocypher/src/monocypher.c $E/Monocypher/src/optional/monocypher-ed25519.c $E/micro-ecc/uECC.c
echo "built device/libverif.so"
