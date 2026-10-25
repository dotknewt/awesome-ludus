# GitLab Bootstrap Privilege Split Implementation Plan

**Goal:** Fix bootstrap without weakening root-only credential storage or GitLab database authentication.

**Architecture:** Root Ruby wrapper owns filesystem checks and durable publication. A readable non-secret Rails helper runs through the ordinary vendor launcher as `git`; bounded private pipes carry the token and an exact non-secret result.

**Tech Stack:** Existing Ansible, embedded Ruby, GitLab Rails models; no new dependencies.

**Spec:** User approved this split in the current session. Diagnosis and architecture evidence: `.superpowers/sdd/2026-10-22-dev1-live/gitlab-retry-diagnostics-20261024/report.md`; oracle session `ses_e91c992fdffeJKrxSNN73JVK2q`.

## Constraints and review focus

- Preserve root-owned `0600` credential, protected parent, scope inclusion (`api`, `create_runner`), root user/name checks, expiration/revocation checks, and 365-day initial expiry.
- Never rotate/delete PATs or regenerate when a named PAT already exists without its credential file.
- Unset inherited `NO_PRIVILEGE_DROP` for Rails. No token in argv, environment, Ansible results, or diagnostics.
- Existing-file validation never rewrites it. Creation publishes only after committed Rails success. Failures after database commit may leave an orphan requiring explicit recovery.
- Bound subprocess runtime/output, serialize wrapper operations, reap timed-out children, require exact success record and zero exit. Preserve final file if failure happens after publication.
- Static and live evidence only. No mocks, simulations, broad validation, commits, or unrelated role edits.

## Task 1: Implement one cohesive helper boundary

Files: `ansible/roles/linux_gitlab_ce/tasks/bootstrap.yml`, `files/bootstrap_api_token.rb`, new `files/bootstrap_api_token_rails.rb`, and scoped static checks under `tests/`.

- [ ] Update static regression contracts first; capture expected failure before implementation.
- [ ] Install root wrapper `0700` and root-owned non-secret Rails helper `0644` under `/usr/local/sbin`; invoke wrapper with `/opt/gitlab/embedded/bin/ruby` as root.
- [ ] Wrapper launches `/opt/gitlab/bin/gitlab-rails runner <helper> <create|validate>` without a shell and with privilege override removed. Pipe token via stdin. Require `LUDUS_BOOTSTRAP_V1 CREATED\n` or `LUDUS_BOOTSTRAP_V1 VALIDATED\n`, matching operation, and zero exit.
- [ ] Wrapper validates/locks protected storage, bounds input/output/runtime, preserves existing credential, and retains exclusive temporary creation, flush/fsync, atomic no-clobber publication using a same-directory hard link, removal of its own temporary name, metadata/content checks, and directory fsync. Preserve the final file after publication even if later checks fail.
- [ ] Rails helper rejects root execution and invalid requests; validates existing model contract or creates using build/set_token/save in transaction, verifies saved token, then emits exact result after commit. No credential filesystem access or secret output.
- [ ] Keep failures sanitized but diagnosable by fixed category; block downstream tasks on wrapper failure.

## Task 2: Verify and review

Fast-generic owns command validation; controller accepts evidence; oracle reviews privilege/lifecycle boundary.

- [ ] Capture changed-file hashes, scoped diff, static test red/green, Ruby syntax checks, YAML lint and file-scoped Ansible lint. No whole-role suite.
- [ ] Inspect all input/output paths and failure ordering independently; correct real defects before upload.
- [ ] Clearly label unexecuted behavioral paths; static tests do not establish runtime compatibility.

## Task 3: Authorized fresh cycle

Live operator owns execution/evidence; controller accepts outcome.

- [ ] Preserve existing sanitized guest logs/credential disposition before destruction.
- [ ] Force-upload changed role(s) using exact installed basename and verify server catalog/content where available.
- [ ] Destroy only range `dev1` using supported CLI; verify terminal destroyed state and retained intended config. Do not remove templates/roles or change configuration.
- [ ] Launch exactly one full `ludus range deploy -r dev1` and monitor logs/status to terminal. Timeout is unknown, not retry permission.
- [ ] Report actual bootstrap/downstream results and gaps. No automatic further fix/upload/deploy on failure. Fresh creation does not establish convergence or injected failure recovery.
