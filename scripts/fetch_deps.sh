#!/bin/sh
# Fetch third-party embedded crypto libraries at the exact commits used in the paper.
set -e
cd "$(dirname "$0")/.."; mkdir -p third_party; cd third_party
get() { [ -d "$1" ] || git clone -q "$2" "$1"; git -C "$1" checkout -q "$3"; echo "$1 @ $3"; }
get Monocypher https://github.com/LoupVaillant/Monocypher e65d27722a43e9ed88da1987f3ad5675503c8cad
get micro-ecc  https://github.com/kmackay/micro-ecc        541b3a78026420a3e369c4c9281c396b5e531113
get tiny-AES-c https://github.com/kokke/tiny-AES-c         23856752fbd139da0b8ca6e471a13d5bcc99a08d
