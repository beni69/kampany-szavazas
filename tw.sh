#!/bin/sh
# wrapper script to execute tailwind cli, silently download it if missing
set -e

if test ! -f ./tailwind.bin; then
    curl -Lo ./tailwind.bin https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.3/tailwindcss-linux-x64
    chmod +x ./tailwind.bin
fi

./tailwind.bin -i tailwind.css -o static/style.css $@
