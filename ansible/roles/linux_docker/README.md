# ludus_install_docker

Installs Docker Engine, the Docker CLI, containerd, Buildx, and Compose from
the official Docker Debian repository. The role also creates the `docker`
group, sets the Ludus `debian` account (UID 1000) to use it as its primary
group, and enables and starts the Docker service.

## Requirements

- Debian with an APT release recognized by Docker's Debian repository.
- Ansible with `ansible.builtin.deb822_repository` support (Ansible Core 2.15
  or later).
- Facts gathered, so `ansible_distribution_release` is available.
- Privilege escalation (`become: true`).

## Role Variables

This role has no configurable variables. The `debian` account is the Ludus
account and is intentionally managed directly.

## Dependencies

None.

## Example Playbook

```yaml
---
- name: Install Docker on a Ludus Debian VM
  hosts: docker_hosts
  become: true
  gather_facts: true
  roles:
    - ludus_install_docker
```

## License

GPLv3

## Troubleshooting: Docker socket access after group changes

If a task adds the Ludus `debian` account to the `docker` group and then uses
`meta: reset_connection`, a subsequent Docker socket operation may report
permission denied. A reset can reconnect with connection variables that have
not been templated, so the refreshed session may not have the expected user or
SSH options. Do not work around this by broadening socket permissions or
running Docker as root.

The documented controller-side workaround is the Ansible Core 2.16.14
`reset_connection` hotfix in
[`docker-socket-reset/`](docker-socket-reset/).
It moves connection-option variable templating into a shared helper used by
normal connection setup and connection reset. The accompanying patch is
available there as
[`ansible-core-2.16.14-reset-connection.patch`](docker-socket-reset/ansible-core-2.16.14-reset-connection.patch).

This patch targets the shared system Ansible installation, not this role. It
was prepared for Ansible Core 2.16.14 and does not address the documented
unsupported Ansible 2.16/Python 3.13 baseline. Review the troubleshooting
document's scope, safeguards, and verification status before considering it;
do not apply it automatically. The incident's precise causal trace and Docker
role behavior after the patch remain unverified.
