Im designing a new ludus blueprint where some ansible roles already exist, some need to be created (or copied from existing and modified)
In addition to the range router, the range must use either "debian-13.5-x64-server-no-template", "ubuntu-24.04.2-x64-server-no-template" or "ubuntu-26.04.1-x64-server-no-template" templates. Default to debian unless a tool or installation guide or requirement suggests ubuntu may be more straight forward.
Range version 0.1 needs these VMs 
- Splunk server
- Malcolm server (use role @ansible/roles/ludus_install_malcolm; no role changes needed)
- Gitlab server (use role @ansible/roles/ludus_gitlab_ce; no role changes needed)