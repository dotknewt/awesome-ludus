# Verify Ludus skills against official documentation

Apply these instructions when reviewing existing Ludus skills or adding or creating new ones, including their reference files. Local skills live under `.opencode/skills/`.

Adapted from [sync-ludus-docs](https://gitlab.com/badsectorlabs/ludus-skills/-/blob/main/.claude/commands/sync-ludus-docs.md). This instruction covers both maintenance and new skill authoring.

## 1. Establish scope and sources

Read the affected skill and its references in full. For a new skill, identify its intended scope and the factual guidance it will contain. Map each relevant topic to current official sources at <https://docs.ludus.cloud>.

Use these entry points and follow relevant links to topic-specific pages:

| Topic | Official entry points |
| --- | --- |
| CLI commands and workflows | <https://docs.ludus.cloud/docs/using-ludus/cli>, <https://docs.ludus.cloud/docs/quick-start/using-cli-locally> |
| Range configuration | <https://docs.ludus.cloud/schemas/range-config.json>, <https://docs.ludus.cloud/docs/configuration> |
| Testing mode | <https://docs.ludus.cloud/docs/quick-start/testing-mode> |
| Environments | <https://docs.ludus.cloud/docs/category/environment-guides> and relevant linked environment pages |
| Troubleshooting | <https://docs.ludus.cloud/docs/category/-troubleshooting> and relevant linked troubleshooting pages |
| Blueprints, templates, roles, snapshots, sharing | The corresponding pages linked from the official documentation navigation |

Fetch the relevant pages during the current task. Record dead links, redirects, and inaccessible sources. Find replacement pages through official navigation or search rather than treating guessed URLs as verified sources.

## 2. Collect evidence

Check commands, flags, configuration fields, allowed values, defaults, prerequisites, supported environments, version-specific behavior, error messages, and links against fetched documentation. For new content, verify factual claims before drafting them.

For each discrepancy, retain:

- Local file and line, with an exact local quote.
- Exact upstream quote and its source URL.
- Any version scope or conflicting official guidance.

For missing coverage, retain the topic and source URL. For content not found upstream, record the local claim and the URLs actually checked. Absence from searched pages alone is not evidence that a claim is false.

If research is delegated, researchers return evidence only: fetched URLs, verbatim discrepancies, missing topics, claims not found upstream, and uncertainties. The editing agent reads the source pages itself before using that evidence. Delegated prose and confidence ratings are not source evidence.

## 3. Write or update verified guidance

Use current official documentation as the authority for documented Ludus behavior. Resolve contradictory pages using their version context and corroborating official sources; report unresolved conflicts rather than choosing silently.

Before each factual edit or addition, have the supporting upstream quote in the editing agent's own context, fetched firsthand. Confirm that any quoted local text actually appears in the file. Re-fetch when the evidence is unavailable or exists only in a research report.

- For factual maintenance of existing skills, preserve headings, organization, and tone. Put additions in the appropriate existing section.
- For new skills or explicitly requested structural changes, organize the material for its intended scope and attach source links to the relevant guidance.
- Distinguish repository-specific procedures and observed implementation behavior from claims about officially documented behavior. Retain their provenance where official documentation does not cover them.
- Leave unsupported proposed guidance out of authoritative instructions and report the uncertainty. Retain existing unverified content for user review unless evidence establishes that it is wrong.

## 4. Verify and report

Re-read every changed region and inspect the diff. Confirm that factual changes have source evidence, examples agree with the documented commands or schema, links point to the intended sources, and surrounding structure remains coherent.

Before completing the task, summarize:

- Skills reviewed or created, changes made, and supporting official URLs.
- Unresolved claims, conflicting guidance, and dead or inaccessible URLs.
- Coverage gaps: relevant topics or pages that could not be checked.

Describe verification as partial when gaps remain. Commit or install skills only when requested by the user or required by the active task.
