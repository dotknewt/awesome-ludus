# Ansible Role: REMnux ([Ludus](https://ludus.cloud))

An Ansible Role that installs [REMnux](https://remnux.org/) on Ubuntu 20.04 systems.

## Requirements

You must have the ubuntu-20.04-x64-server-template built on your ludus host. You can add it with:

```
git clone https://gitlab.com/badsectorlabs/ludus.git
cd ludus/templates
ludus templates add -d ubuntu-20.04-x64-server
ludus templates build
```

## Role Variables

None.

## Dependencies

None.

## Example Playbook

```yaml
- hosts: remnux_hosts
  roles:
    - ludus_install_remnux
```

## Example Ludus Range Config

```yaml
ludus:
  - vm_name: "{{ range_id }}-REMnux"
    hostname: "{{ range_id }}-REMnux"
    template: ubuntu-20.04-x64-server-template
    vlan: 99
    ip_last_octet: 3
    ram_gb: 6
    cpus: 4
    linux: true
    roles:
      - ludus_install_remnux
```

## License

GPLv3

## Author Information

This role was created by [Bad Sector Labs](https://github.com/badsectorlabs), for [Ludus](https://ludus.cloud/).
