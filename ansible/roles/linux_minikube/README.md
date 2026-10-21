# ludus_install_minikube

Installs the Minikube package, the latest stable `kubectl` binary, and Helm on
Debian. It installs tooling only; it does not create or configure a Kubernetes
cluster.

## Requirements

- Debian on amd64, matching the Minikube and `kubectl` download artifacts.
- Ansible Core 2.15+ with the `ansible.builtin` modules used by this role.
- Fact gathering enabled: the `ludus_install_docker` dependency requires
  `ansible_distribution_release`.
- Privilege escalation (`become: true`).
- Internet access to the Minikube, Kubernetes, and Helm download endpoints.

## Role Variables

This role has no configurable variables.

## Dependencies

This role depends on `ludus_install_docker`, which installs Docker and the
`curl` executable used by Helm's upstream installer. Both local roles must be
installed or otherwise discoverable through Ansible's configured role paths.

## Example Playbook

```yaml
---
- name: Install Minikube tooling on a Ludus Debian VM
  hosts: minikube_hosts
  become: true
  gather_facts: true
  roles:
    - ludus_install_minikube
```

## License

GPLv3
