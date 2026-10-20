"""Pure parser for Splunk input stanza headers that bind TCP ports."""

from __future__ import annotations

import re


_LISTENER = re.compile(r"^\[(?P<kind>splunktcp(?:-ssl)?|tcp(?:-ssl)?)(?:://|:)(?P<endpoint>.+)\]$")


def receiver_listener_ports(text: str) -> list[str]:
    """Extract ports from cooked/raw TCP and SSL listener stanza headers.

    Disabled stanzas remain collisions: the role must not claim or edit an
    existing unmanaged listener just because its current state is disabled.
    """
    ports: list[str] = []
    for line in text.splitlines():
        header = line.strip()
        match = _LISTENER.fullmatch(header)
        if match is None:
            continue
        endpoint = match.group("endpoint")
        port = endpoint if endpoint.isdecimal() else endpoint.rsplit(":", 1)[-1]
        if port.isdecimal():
            ports.append(str(int(port)))
    return ports


class FilterModule:
    def filters(self):
        return {"ludus_splunk_server_receiver_listener_ports": receiver_listener_ports}
