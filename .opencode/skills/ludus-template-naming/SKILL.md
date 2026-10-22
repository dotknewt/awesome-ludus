---
name: ludus-template-naming
description: Use when naming, renaming, reviewing, or validating Ludus Packer OS templates, especially when legacy names have ambiguous locale, role, edition, release, or feature tokens such as no or no-security-updates.
---

# Ludus Template Naming

This skill defines **repository policy**, not a universal Ludus naming rule.
Apply one canonical grammar to Ludus Packer template directories, top-level
`.pkr.hcl` files, `vm_name` values, and exact consuming references. Preserve the
template's semantics; normalize only their representation.

## Canonical Grammar (Repository Policy)

Use lowercase ASCII letters, digits, hyphens, and dots only; never underscores.
Use hyphens between fields and within compound releases or multiword qualifiers.
Keep numeric release components dot-separated. Both basenames and final built
names must be DNS-compatible: each dot-separated label is 1–63 characters,
starts and ends with a letter or digit, and the full textual name is at most
253 characters without a trailing root dot. Include the built `-template`
suffix when checking these limits; it extends the final label.

| Family | Shape |
| --- | --- |
| Linux | `<os>-<release>-<arch>-<role>[-<qualifier>...]-<locale>` |
| Windows client | `windows-<release>-<arch>[-<qualifier>...]-<locale>` |
| Windows Server | `windows-server-<release>-<arch>[-<qualifier>...]-<locale>` |
| Named FLARE environment | `flare-vm-<locale>` |

Accept `ubuntu`, `debian`, `kali`, `windows`, and `windows-server`. Use `x64`
or `arm64` for architecture. Require `desktop` or `server` as the Linux role.
Encode Windows Server's role in the family prefix and omit a separate role from
Windows client names.

Require a final lowercase two-letter locale token, including default `us`.
Treat that token as filename metadata only. Validate the physical keyboard,
XKB layout and variant, or Windows InputLocale independently.

Use dots for numeric releases such as `24.04.2`, `13.2`, and `2024.4`. Use a
hyphen when a release combines a numeric product release with a semantic
alphanumeric part, as in `11-22h2`. Use hyphens for multiword qualifiers,
as in `no-security-updates`. The architecture token ends the release; hyphens
alone do not distinguish separate qualifiers from words within one qualifier.

## Examples

```text
ubuntu-24.04.2-x64-desktop-no
debian-13.2-x64-server-no
kali-2024.4-x64-desktop-no
windows-11-22h2-x64-enterprise-no
windows-server-2019-x64-no-security-updates-us
windows-server-2019-x64-no-security-updates-no
flare-vm-no
flare-vm-us-template
```

Set the top-level `.pkr.hcl` basename equal to the directory basename. Set the
built template name to that basename plus exactly one `-template` suffix.

## Read-Only Classification and Construction

**REQUIRED SUB-SKILL:** Operational template workflows must load this skill.

1. Inspect the complete template directory, top-level `.pkr.hcl`, installer
   answer files, and exact consuming references before interpreting a legacy
   basename.
2. Classify an explicitly named environment before applying an OS-shaped grammar.
   Preserve `flare-vm-no` exactly, and recognize only `flare-vm-<locale>` plus
   its built `-template` form; do not expand FLARE into OS, release,
   architecture, edition, or feature fields.
3. For OS-shaped names, classify the OS family, release, architecture, Linux
   role when applicable, qualifiers, and locale from file content rather than
   token position. Add a qualifier only when the template provides direct
   evidence for it: retain `enterprise`, explicitly identified
   `no-security-updates`, and genuine `tpm` when a TPM device is configured.
   Never infer `tpm` from bypass registry commands, or harvest installer and
   provisioner settings as naming qualifiers.
4. Omit `tpm_bypas`, `tpm_bypass`, `standard`, `standard_evaluation`, and
   `desktop_experience` from names. These are not naming fields; do not change
   the underlying template settings while omitting them. Their hyphenated
   spellings (`tpm-bypas`, `tpm-bypass`, `standard-evaluation`, and
   `desktop-experience`) remain excluded too; never add `flare-vm` as an OS qualifier.
5. Ask one short question when evidence does not resolve a token. Never assume
   `no` means Norwegian; it can belong to `no-security-updates`, while the
   locale requires installer or other direct locale evidence.
6. Construct and validate the proposed basename using the family-specific
   shape and separators above. Standalone naming/normalization preserves every
   classified semantic field. An operational caller supplies its authorized
   semantic delta (for example, a new release or locale): classify the source
   first, then construct the proposed target by applying that delta and
   preserving all other classified semantics. This phase is read-only: report
   the proposed identity and evidence gaps without renaming files, editing
   `vm_name`, or changing references.

Do not change locale, role, edition, feature, release, or architecture merely
to satisfy naming. Do not create backward-compatible aliases unless explicitly
requested. A standalone naming or normalization request still proceeds to the
application phase below; read-only construction separates the decision from
mutation, it does not discard the requested rename.

## Apply a Requested Rename

Apply only after the user has requested normalization/renaming or an operational
workflow has reached its explicit mutation step. The operational workflow owns
whether it copies or renames, the mutation sequence, and the scope of reference
updates; follow that workflow rather than applying the standalone rename
sequence to its source. Before any mutation, confirm
the target directory and target `.pkr.hcl` do not exist, including unchanged
named-environment identity collisions. Then rename the directory and top-level
`.pkr.hcl`, set `vm_name` to the validated basename plus one `-template`
suffix, and update exact old-name references. Do not blindly replace short
tokens. Search for the old full basename and inspect every remaining match.

## Validate Names

Resolve `scripts/validate_template_name.py` relative to this `SKILL.md`, not
relative to the caller's current working directory. Execute that resolved path
on both the basename and built name:

```bash
python3 /absolute/resolved/skill/path/scripts/validate_template_name.py \
  ubuntu-24.04.2-x64-desktop-no \
  ubuntu-24.04.2-x64-desktop-no-template
```

Interpret validator success as syntax validation only. Manually verify that
the final locale matches installer evidence, directory and `.pkr.hcl` basenames
match, `vm_name` is exact, and all consuming references were updated. The
validator never reads HCL, infers semantics, or renames files.

## Common Mistakes

| Mistake | Correction |
| --- | --- |
| Put locale before Linux role | Put locale in the final field |
| Write `13-2` or `13_2` | Write numeric release `13.2` |
| Write `11_22h2` or `no_security_updates` | Write `11-22h2` or `no-security-updates` |
| Check only the basename's DNS length | Check the final `-template` name too |
| Omit default US locale | Append explicit `us` |
| Infer locale from `no` alone | Inspect installer keyboard configuration |
| Add `-template` to files | Add it only to the built `vm_name` |

## Completion Report

Report the old and new basenames, semantic field classification and evidence,
every renamed or edited file, updated references, validator results, and checks
that could not run.
