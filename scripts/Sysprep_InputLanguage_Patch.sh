#!/usr/bin/env bash
# Set the InputLocale in Ludus's sysprep answer file (oob-disable.xml)
# so sysprepped Windows VMs keep your keyboard instead of resetting to US.
# Only InputLocale is changed; SystemLocale/UILanguage/UserLocale stay as they are.
#
# Usage:  sudo ./set-sysprep-inputlocale.sh [INPUT_LOCALE] [FILE]
#   INPUT_LOCALE  default 0409:00000414  (en-US language, Norwegian keyboard)
#   FILE          default /opt/ludus/ansible/range-management/files/windows/sysprep/oob-disable.xml
#
# Note: a Ludus update can overwrite this file; re-run the script after updating.

set -euo pipefail

LOCALE="${1:-0409:00000414}"
FILE="${2:-/opt/ludus/ansible/range-management/files/windows/sysprep/oob-disable.xml}"

# Accept either a keyboard ID (0409:00000414, several joined with ';') or a tag (nb-NO)
if ! [[ "$LOCALE" =~ ^([0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}|[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*)(;([0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}|[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*))*$ ]]; then
    echo "Invalid input locale: $LOCALE" >&2
    exit 1
fi

if [[ ! -f "$FILE" ]]; then
    echo "File not found: $FILE" >&2
    exit 1
fi

count=$(grep -c '<InputLocale>' "$FILE" || true)
if [[ "$count" -eq 0 ]]; then
    echo "No <InputLocale> element found in $FILE; nothing changed." >&2
    exit 1
fi

if grep -q "<InputLocale>${LOCALE}</InputLocale>" "$FILE" && [[ "$(grep -c "<InputLocale>${LOCALE}</InputLocale>" "$FILE")" -eq "$count" ]]; then
    echo "InputLocale already set to ${LOCALE} in $FILE"
    exit 0
fi

backup="${FILE}.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$FILE" "$backup"
echo "Backup: $backup"

sed -i -E "s|<InputLocale>[^<]*</InputLocale>|<InputLocale>${LOCALE}</InputLocale>|g" "$FILE"

# Verify the XML still parses; restore the backup if not
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -I -c 'import sys, xml.dom.minidom as m; m.parse(sys.argv[1])' "$FILE"; then
        echo "XML no longer parses; restoring backup." >&2
        cp -p "$backup" "$FILE"
        exit 1
    fi
fi

echo "Updated $FILE:"
grep -n -E '<(InputLocale|SystemLocale|UILanguage|UserLocale)>' "$FILE"
