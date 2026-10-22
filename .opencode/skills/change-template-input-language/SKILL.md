---
name: change-template-input-language
description: Use when changing a Ludus Packer template's physical keyboard layout or installer input-language setting for Windows, Debian, Kali, Ubuntu, or a named FLARE environment.
---

# Change Template Input Language

Convert an existing template to a different keyboard input language without
changing its display language, system locale, regional format, or ISO unless
the user explicitly requests those changes too.

## Required Inputs

Determine these values before editing:

- Exact template under `awesome-ludus-sauce/templates/`
- Requested physical keyboard layout and, when relevant, its variant
- Existing and target locale tokens used in the template name
- OS-specific installer value: Windows input locale or Linux XKB layout and
  variant

Keyboard layout, language locale, and filename token are different identifier
systems. Do not assume one value is valid in all three. Ask one short question
if the requested physical layout is ambiguous, such as ANSI US versus British,
standard versus Dvorak, or a locale with multiple national layouts.
**REQUIRED SUB-SKILL:** Load `ludus-template-naming` and use its **Read-Only
Classification and Construction** and **Validate Names** sections for filename
classification and target construction. This is repository naming policy, not
a universal Ludus rule. Classify the source first, then construct the proposed
target with the requested locale as the authorized semantic delta, preserving
all other classified semantics. Stop before mutation and ask one short question
if directory and installer evidence do not resolve a legacy basename token.
Classification and construction are read-only; do not rename during this phase.

## Identifier Lookup

Validate values before editing. Do not invent them.

- Ubuntu, Debian, and Kali use XKB identifiers. Use `reference/xorg.lst` as
  the bundled reference. Layouts are listed under `! layout`; variants are
  listed under `! variant` and name their compatible layout before the
  description. Valid XKB options are listed under `! option`. The Ubuntu
  autoinstall `layout` and `variant` fields map to `XKBLAYOUT` and
  `XKBVARIANT`.
- If local XKB rules are unavailable, use the target release's
  `keyboard-configuration` package or official Ubuntu/Debian documentation.
- Windows `InputLocale` accepts a supported BCP 47 language tag for that
  language's default keyboard, such as `en-US`, or a locale-ID and keyboard
  layout pair such as `0409:00000409`. Multiple values are semicolon-separated
  and the first is the default. Confirm values using Microsoft documentation
  or the target Windows image's keyboard-layout registry data.
- Use the naming skill's validator for both the proposed basename and built
  name. Keyboard identifiers and the physical layout remain independently
  validated below; a filename locale does not prove the keyboard layout.

For standard Norwegian Bokmal QWERTY, use:

| Context | Value |
| --- | --- |
| Template name token | `no` |
| Windows `InputLocale` | `nb-NO` |
| Linux XKB layout | `no` |
| Linux XKB variant | empty string |

The standard Norwegian layout is already QWERTY. Do not use `nb` as an XKB
layout and do not use `variant: qwerty`; neither identifies the standard
Norwegian XKB keyboard.

## Required Rename

### Named FLARE environment

1. Detect `flare-vm-<locale>` before applying an OS-shaped grammar. Preserve the
   FLARE identity and schema, but replace only the final locale with the
   requested validated locale. For example, rename `flare-vm-no` to
   `flare-vm-us`; set the corresponding `vm_name` to
   `flare-vm-us-template`.
2. Stop and report a conflict if the target directory or target top-level
   `.pkr.hcl` already exists. Do not merge into or overwrite either target.
3. Preserve the existing FLARE identity schema and underlying template
   settings; do not expand the named environment into OS-shaped fields.
4. Rename the directory and top-level `.pkr.hcl` to the new
   `flare-vm-<locale>` basename, update exact identity references, and leave
   release-neutral support files unchanged.

### Generic OS template

1. Use the naming skill to classify the complete template and construct the
   target basename with only the requested locale change. Its decision also
   preserves existing semantic fields; do not interpret or rewrite naming rules
   here.
2. Stop and report a conflict before renaming if either the target directory or
   target top-level `.pkr.hcl` already exists. Do not merge into or overwrite
   either target.
3. Rename the template directory to the target basename.
4. Rename its top-level `.pkr.hcl` file so its basename exactly matches the
   renamed directory.
5. Do not rename release-neutral support files such as `Autounattend.xml`,
   `kali-preseed.cfg`, `debian-13-preseed.cfg`, or `http/user-data`.

This workflow changes the existing template in place by default. Copy it instead
only if the user explicitly asks to retain both locale variants. Apply the
already-classified target only after this choice is settled and the collision
check passes; for an explicitly requested copy, perform the same collision
check against the copy target before copying or editing anything.

## Required Packer Edits

Inspect the complete renamed `.pkr.hcl`; do not limit the change to `vm_name`.

1. Change the `vm_name` default to `<target-basename>-template`.
   For the named FLARE branch, use the new `flare-vm-<locale>-template` value
   and do not apply release or OS source-label edits.
2. Replace locale-bearing internal source labels when they contain the old
   template locale. Update the matching `build.sources` reference in the same
   edit. Leave release-neutral labels alone.
3. Update old template basenames or locale-bearing file paths found in string
   values.
4. Update installer boot-command keyboard values that would override or race
   the answer file:
   - Debian: update `keymap=<xkb-layout>` if present.
   - Kali: update every keyboard parameter present, commonly
     `console-keymaps-at/keymap`, `kbd-chooser/method`, and
     `keyboard-configuration/xkb-keymap`.
5. Do not change `iso_url`, `iso_checksum`, UI language, system locale,
   timezone, country, or `template_description` unless one contains an actual
   stale template identifier or the user requested broader localization.

Search before replacing short tokens such as `us` or `no`; never perform a
blind repository-wide replacement.

## OS-Specific Answer Files

### Windows

Edit every active `<InputLocale>` element in `Autounattend.xml`, across every
configuration pass in which it appears:

```xml
<InputLocale>nb-NO</InputLocale>
```

Replace the element text regardless of its current value. Leave
`SetupUILanguage`, `SystemLocale`, `UILanguage`, and `UserLocale` unchanged for
an input-language-only request. Preserve XML namespaces and formatting.

### Debian

Find the actual preseed filename rather than assuming it is literally
`preseed.cfg`. Change the active keyboard selection to the validated XKB
layout:

```text
d-i keyboard-configuration/xkb-keymap select no
```

Also update any `keymap=` boot argument in the `.pkr.hcl` as described above.
Do not change `debian-installer/locale` for an input-language-only request.

### Kali

Find the actual preseed filename and change the active keyboard selection:

```text
d-i keyboard-configuration/xkb-keymap select no
```

Update all keyboard-related boot arguments in the `.pkr.hcl` to the same XKB
layout. Do not change `debian-installer`, `locale`, or language-support values
for an input-language-only request.

### Ubuntu

Edit `http/user-data`. `keyboard` must be a mapping nested under `autoinstall`,
and `layout` and `variant` must be nested beneath `keyboard`:

```yaml
autoinstall:
  version: 1
  keyboard:
    layout: no
    variant: ""
```

Use the validated XKB variant exactly. Use `variant: ""` for the standard
layout. For comparison, standard US QWERTY is `layout: us` with
`variant: ""`; `layout: en` with `variant: us` is not the correct XKB pair.
Leave the top-level autoinstall `locale` unchanged for an
input-language-only request.

## Verification

Before finishing:

1. For the named FLARE branch, confirm the target is exactly
   `flare-vm-<new-locale>` and that only its final locale changed; do not
   invent an OS-shaped identity.
2. For the generic OS branch, confirm the target basename and built name pass
   the naming skill's validator and only the requested locale differs from the
   classified source.
3. Confirm the directory basename and `.pkr.hcl` basename are identical.
4. Confirm the built name and `vm_name` default use the validated target
   basename plus exactly one `-template` suffix.
5. Search the converted template for the old full basename and old keyboard
   values. Classify each remaining match; ISO filenames and prose may
   legitimately contain language text.
6. Confirm all Windows `InputLocale` elements have the requested value, or all
   Linux installer and boot-command keyboard values agree.
7. For Ubuntu, verify YAML indentation and confirm `layout` and `variant` are
   children of `keyboard`, which is a child of `autoinstall`.
8. Run `packer fmt -check <target.pkr.hcl>` when Packer is installed. If it
   fails only because formatting differs, run `packer fmt <target.pkr.hcl>` and
   check again.
9. Run an available YAML parser or autoinstall schema validator for Ubuntu and
   an XML parser for Windows.
10. Run `git diff --check` and inspect the complete diff for unintended locale,
   ISO, timezone, or display-language changes.

Report the old and new template basenames, the requested physical layout, the
platform-specific values used, every file renamed or edited, and any checks
that could not be run.
