#!/usr/bin/bash
# ludus_configure_bridge now automates these settings for the current range.
brctl setageing vmbr1002 0
ip link set vmbr1002 promisc on
