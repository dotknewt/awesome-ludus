#!/usr/bin/bash
URL='https://docs.remnux.org/install-distro/install-from-scratch#get-remnux-installer'
curl -# -L "${URL}" 2> '/dev/null' |
grep -P -o -e '([[:<:]][[:alnum:]]{64}[[:>:]])' |
head -n 1
