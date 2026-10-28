# GitLab CE and Runner range example

This example separates GitLab CE and the Docker-executor Runner. It uses the
`no-debian-13.5-x64-server-template` template already used in repository range
examples. Both roles and templates must be available on the target Ludus
server before deployment.

The server's explicit URL (`http://10.<range-second-octet>.10.10`) is also the
Runner URL. `bootstrap_host` names the server VM's inventory identity, and
`depends_on` orders the Runner role after `linux_gitlab_ce`. CE creates the
protected bootstrap credential; the Runner role creates a minimal demo project
and project runner. No credential is included here.

The CE role consumes `ludus_gitlab` as a complete mapping rather than merging
its defaults. This example therefore explicitly supplies the existing
`smtp`, `email_from`, `displayname`, `replyto`, and `emailroot` settings as well
as the URL and bootstrap option.

The Runner role installs distribution `docker.io` itself and configures its
own `gitlab-runner` account for Docker access. Do not add the
`linux_install_docker` sibling role: it is unnecessary and
hardcodes a Debian login account that this role intentionally does not assume.

The role metadata declares `linux_gitlab_ce` and `linux_gitlab_runner` as role
identities (the latter is authored by `dotknewt`). Metadata alone does not prove
those identities are installed under those names on a particular Ludus server;
confirm the installed role catalog before using this example. Likewise, Ludus
documents `depends_on` ordering but does not guarantee delegated `hostvars` and
protected-file access across separate role playbooks. The bootstrap delegation
path may therefore require runtime verification; alternatively provide a
protected API token out of band or use an existing runner authentication token
as documented by the role. No live server access or deployment was performed
for this example.
