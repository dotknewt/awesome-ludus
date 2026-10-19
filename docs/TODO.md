# TODO

## Docs
- [ ] Create project setup instructions that can be fed to an agent to configure and install MCPs and skills
    - https://gitlab.com/badsectorlabs/ludus-mcp; replace `<YOUR_API_KEY>` with `{file:~/<PATH_TO_A_FILE>}`;gitignored if inside repo
    - https://gitlab.com/badsectorlabs/ludus-skills;install to project if not already present

## Roles
- [ ] Fix ludus_install_docker failing due to docker socket permission error on first run (fixed by redeploy)

### New
- [ ] Create a kubernetes installer role
- [ ] Create gitlab builder/runner/worker roles (targeting docker/kubernetes as well as "native")
- [ ] Create ludus role for https://github.com/S3N4T0R-0X0/BEAR-C2
