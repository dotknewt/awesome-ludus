# Ansible Role: GitLab Community Edition (Ludus)

An Ansible Role that installs a Gitlab CE instance and optionnaly create groups and users.

The role performs the following actions:
- Setup a repository for GitLab
- Install the selected version or the latest version of GitLab Community Edition
- Configure GitLab Community Edition
- Optionnaly, can create arbitrary groups and users

## Requirements

None.

## Role Variables

Available variables are listed below, along with default values (see `defaults/main.yml`):

    # URL where the instance will be exposed
    ludus_gitlab.url: http://localhost:8080

    # Name of the instance
    ludus_gitlab.displayname: MyCompany Gitlab

    # SMTP Server to configure so Gitlab can send emails
    ludus_gitlab.smtp: 127.0.0.1

    # From email adress for messages sent by Gitlab
    ludus_gitlab.email_from: gitlab@example.com

    # From email adress for messages sent by Gitlab
    ludus_gitlab.replyto: no-reply@example.com

    # Root email account
    ludus_gitlab.emailroot: admin@example.com


By default, the latest version is installed. Define the variable `version` with the value in the range if you need a specific version.

    # Optionnal: Gitlab version to install
    ludus_gitlab.version: 16.7.0


For the groups and users, they are optionnaly configured in `ludus_gitlab.groups` and `ludus_gitlab.users`.

    # Optionnal: Name of the group to create
    ludus_gitlab.groups.name: MyGroup

    # Optionnal: Login of the user to create
    ludus_gitlab.users.name: jdoe

    # Optionnal: Display name of the user to create
    ludus_gitlab.users.display_name: John Doe

    # Optionnal: Password of the user to create
    ludus_gitlab.users.password: aA8MaQBCtBtPYAFh

    # Optionnal: Email of the user to create
    ludus_gitlab.users.email: jdoe@myrange.corp

    # Optionnal: Group to apply to the user to create
    ludus_gitlab.users.group: MyGroup

    # Optionnal: Access level of the user to create
    ludus_gitlab.users.access_level: maintainer

## Example Ludus Range Config

```yaml
  - vm_name: "{{ range_id }}-GIT-01"
    hostname: "{{ range_id }}-GIT-01"
    template: debian-12-x64-server-template
    vlan: 55
    ip_last_octet: 2
    dns_rewrites: 
      - git.myrange.corp
    ram_gb: 8
    cpus: 2
    linux: true
    testing:
      snapshot: true
      block_internet: false
    roles:
      - ludus-gitlab-ce
    role_vars:
      ludus_gitlab:
        version: 16.7.0
        smtp: 1.2.3.4
        email_from: gitlab@myrange.corp
        emailroot: admin@myrange.corp
        displayname: Gitlab MyRange
        replyto: no-reply@myrange.corp
        url: http://git.myrange.corp
        groups:
          - name: IT
          - name: Engineering
        users:
          - name: jdoe
            display_name: John Doe
            password: aA8MaQBCtBtPYAFh
            email: jdoe@myrange.corp
            group: Engineering
            access_level: maintainer
          - name: msmith
            display_name: Mike Smith
            password: 25H60eORSggFfH2Y
            email: msmith@myrange.corp
            group: IT
            access_level: maintainer
```

## License

GPLv3

## Author Information

This role was created by [Cyblex Consulting](https://github.com/Cyblex-Consulting), for [Ludus](https://ludus.cloud/).