---
name: update-os-template
description: Use when creating a new Ludus Packer OS-release template by copying a compatible existing template, including release-specific ISO metadata, Packer identifiers, and answer-file or boot changes.
---

# Update An OS Template

Create a template for a newly released OS by cloning the newest compatible
template. Preserve the source template's structure and make the smallest
release-specific change.

## Required Inputs

Determine these values from the request and repository before editing:

- OS family and new release version
- Templates directory: `awesome-ludus-sauce/templates/`
- Exact installation ISO URL
- Publisher-provided checksum for that exact ISO

Ask one short question if the OS, release, edition, architecture, locale, or
template variant is ambiguous. Never guess an ISO checksum.

## Workflow

1. Inspect `awesome-ludus-sauce/templates/` for directories belonging to the
   requested OS family. Do not use the deprecated workspace-level
   `templates/` directory.
2. Filter candidates to the same variant as the requested target. Match the
   architecture, desktop/server role, locale, edition, and feature suffix.
3. Sort release versions semantically, not lexicographically, and choose the
   newest compatible template as the source.
4. Read its `.pkr.hcl` and inspect all files in the template directory for
   release-specific references before copying.
5. **REQUIRED SUB-SKILL:** Load `ludus-template-naming` and use its
   **Read-Only Classification and Construction** and **Validate Names** sections
   to propose and validate the target basename. This is repository naming
   policy, not a universal Ludus rule. For an OS-shaped source, classify its
   semantics first, then construct the target using the requested new release
   while preserving all other classified semantics. Preserve the old source
   directory unchanged; classify and construct before copying, without applying
   the rename to the source. If the source is
   `flare-vm-no` or another `flare-vm-<locale>` identity (including a terminal
   `-template` suffix), stop before selecting a target name. Require and record
   an explicit naming decision: either retain the unchanged identity, or specify
   a new named-environment identity and schema. Never derive a release-bearing
   FLARE name or silently reuse the unchanged identity for an OS upgrade. Do
   not continue until that decision is recorded. For OS-shaped sources, ask for
   an explicit schema decision if their family is outside the naming skill's
   supported families.
6. Stop and report the conflict if the target directory or target `.pkr.hcl`
   already exists. Do not merge into or overwrite an existing template.
7. Copy the entire source directory to the new directory so supporting files,
   scripts, HTTP assets, and answer files are retained.
8. Rename the copied `.pkr.hcl` so its basename exactly matches the target
   directory name.
9. In the copied `.pkr.hcl`, update only these values unless another change
   is demonstrably required for the new release:
   - `iso_checksum`: use the checksum algorithm and digest published for the
     exact ISO. Keep the Packer format `<algorithm>:<digest>`.
   - `iso_url`: use the exact official or project-approved ISO URL. For Debian,
     apply the archive-path rule below.
   - `vm_name`: use `<target-template-name>-template`.
   - `template_description`: replace the old OS release with the new release
     while preserving the existing description format and dynamic build date.
   - For Ubuntu, rename the `proxmox-iso` source label to match the target
     major and minor release with punctuation removed. For example, Ubuntu
     `26.04.1` uses `source "proxmox-iso" "ubuntu2604"`. Update every exact
     reference to that label, including entries in `build.sources`.
10. Search the copied directory for the old full template name, old release,
    old ISO URL, and old checksum. Do not blindly replace matches: distinguish
    release-neutral identifiers from values that would break the new release.
11. If a major OS release requires other changes, such as an answer-file path,
    boot command, or installer behavior, explain the concrete incompatibility
    and make only the necessary additional edits. Except for the required
    Ubuntu source-label update, do not rename internal identifiers merely for
    cosmetic consistency.

## Debian ISO URLs

For Debian templates, always store the ISO URL using Debian's versioned archive
path, matching the existing templates:

```text
https://cdimage.debian.org/cdimage/archive/<version>/amd64/iso-cd/debian-<version>-amd64-netinst.iso
```

The current release may initially be discovered at a URL such as:

```text
https://cdimage.debian.org/cdimage/release/13.6.0/amd64/iso-cd/debian-13.6.0-amd64-netinst.iso
```

Convert it to the durable archive form before writing `iso_url`:

```text
https://cdimage.debian.org/cdimage/archive/13.6.0/amd64/iso-cd/debian-13.6.0-amd64-netinst.iso
```

Change only the `release` path segment to `archive`; preserve the exact version,
architecture, ISO type, and filename. Obtain the checksum for that exact ISO.

## Checksum Rules

- Prefer the OS publisher's checksum manifest over third-party pages.
- Match the checksum by the ISO's exact filename.
- Prefer a signed manifest and verify its signature when tooling and publisher
  keys are available.
- If only a downloaded ISO is available, hash it locally with the manifest's
  algorithm and compare it before recording the value.
- Never reuse the previous release's digest or fabricate a digest from the URL.

## Verification

Before finishing:

1. Confirm the target basename and built name pass `ludus-template-naming`'s
   validator. If the source is a named `flare-vm-<locale>` environment, confirm
   that the explicit naming decision was recorded before any target name was
   chosen and that no release, OS, architecture, edition, or feature was inferred.
2. Confirm the target directory and `.pkr.hcl` basename are identical.
3. Confirm `vm_name` is the validated target basename plus exactly one
   `-template` suffix.
4. Confirm `template_description` names the new OS release and no longer names
   the source release.
5. For Ubuntu, confirm the `proxmox-iso` source label matches the target major
   and minor release and every reference uses the new label.
6. Confirm the ISO URL's filename is the file matched in the checksum manifest.
7. For Debian, confirm `iso_url` uses `/cdimage/archive/<version>/`, not
   `/cdimage/release/<version>/`.
8. Confirm the checksum has the declared algorithm prefix and expected digest
   length.
9. Run `packer fmt -check <target.pkr.hcl>` when Packer is installed. If it
   fails only because formatting differs, run `packer fmt <target.pkr.hcl>` and
   check again.
10. Run `git diff --check` and inspect the resulting diff to ensure the source
   template was not modified and no unrelated files changed.

Report the source and target template names, ISO URL, checksum source, files
changed, and any verification that could not be run.
