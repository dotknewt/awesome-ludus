"""Strict numeric filters for bounded collector queue configuration."""

import re

from ansible.errors import AnsibleFilterError


MAX_DECIMAL_DIGITS = 13
TYPE_ERROR = "Queue value must be an integer or canonical decimal string."
FORMAT_ERROR = "Queue value must be canonical unsigned ASCII decimal."
BOUNDS_ERROR = "Queue value is outside the permitted range."


def _parse_bounded_decimal(value, minimum, maximum):
    if isinstance(value, bool):
        raise AnsibleFilterError(TYPE_ERROR)

    if isinstance(value, int):
        try:
            parsed = int(value)
        except Exception:
            raise AnsibleFilterError(TYPE_ERROR) from None
    elif isinstance(value, str):
        if len(value) > MAX_DECIMAL_DIGITS:
            raise AnsibleFilterError(FORMAT_ERROR)
        if re.fullmatch(r"(?:0|[1-9][0-9]*)", value, flags=re.ASCII) is None:
            raise AnsibleFilterError(FORMAT_ERROR)
        try:
            parsed = int(value, 10)
        except Exception:
            raise AnsibleFilterError(FORMAT_ERROR) from None
    else:
        raise AnsibleFilterError(TYPE_ERROR)

    if parsed < minimum or parsed > maximum:
        raise AnsibleFilterError(BOUNDS_ERROR)
    return parsed


class FilterModule:
    @staticmethod
    def queue_size(value):
        return _parse_bounded_decimal(value, 1, 2147483647)

    @staticmethod
    def queue_disk_mib(value):
        return _parse_bounded_decimal(value, 200, 8796093022207)

    def filters(self):
        return {
            "splunk_container_queue_size": self.queue_size,
            "splunk_container_queue_disk_mib": self.queue_disk_mib,
        }
