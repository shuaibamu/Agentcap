#!/bin/sh
# Cross-compile all verifiers for Cortex-M0+ (ARMv6-M), Cortex-M4 (ARMv7E-M) and RV32IMC.
cd "$(dirname "$0")"; E=../third_party
INC="-Istub -I$E/Monocypher/src -I$E/Monocypher/src/optional -I$E/micro-ecc -I$E/tiny-AES-c -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256k1=0"
COMMON="-ffreestanding -fno-builtin -ffunction-sections -fdata-sections -fomit-frame-pointer $INC"
mkdir -p mcu
for arch in m0p m4 rv32; do
 case $arch in
  m0p) T="--target=thumbv6m-none-eabi -mcpu=cortex-m0plus -mthumb -mfloat-abi=soft -DuECC_PLATFORM=uECC_arch_other";;
  m4)  T="--target=thumbv7em-none-eabi -mcpu=cortex-m4 -mthumb -mfloat-abi=soft";;
  rv32) T="--target=riscv32-unknown-elf -march=rv32imc -mabi=ilp32 -mno-relax -DuECC_PLATFORM=uECC_arch_other";;
 esac
 for opt in O2 Os; do for s in agentcap agentcap_opt macaroon ucan jwt tedpop acesym; do
  SRC="bench.c verif.c sha256.c rt.c"; D=""; SC=$s
  [ $s = agentcap_opt ] && D="-DOPT"
  [ $s = ucan ] && { SRC="$SRC $E/Monocypher/src/monocypher.c $E/Monocypher/src/optional/monocypher-ed25519.c"; D="-DWITH_ED25519"; }
  [ $s = jwt -o $s = tedpop ] && { SRC="$SRC $E/micro-ecc/uECC.c"; D="-DWITH_P256"; }
  [ $s = acesym ] && { SRC="$SRC aesccm.c $E/tiny-AES-c/aes.c"; D="-DWITH_CCM"; }
  clang $T $COMMON -$opt $D -DSCHEME=v_$SC $SRC -nostdlib -fuse-ld=lld -Wl,-T,m4.ld -Wl,--gc-sections -o mcu/$s.$arch.$opt.elf 2>&1 | grep -E "error" | head -3
 done; done
done
# cache-size variants of AgentCap-opt for the cache-sizing experiment (Cortex-M4, -O2)
T="--target=thumbv7em-none-eabi -mcpu=cortex-m4 -mthumb -mfloat-abi=soft"
for N in 1 2 4 8 16; do
 clang $T $COMMON -O2 -DOPT -DCACHE_N=$N -DSCHEME=v_agentcap_opt bench.c verif.c sha256.c rt.c -nostdlib -fuse-ld=lld -Wl,-T,m4.ld -Wl,--gc-sections -o mcu/agentcap_opt_c$N.m4.O2.elf 2>&1 | grep -E "error" | head -3
done
ls mcu | wc -l
