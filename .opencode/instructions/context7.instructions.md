---
description: 'Use Context7 or equivalent authoritative sources for current external documentation when local context is insufficient'
applyTo: '**'
---

# Context7-Aware Development

Use Context7 proactively when a task depends on authoritative, current, version-specific external documentation that is not present in the workspace context. If Context7 is unavailable, use the available web or documentation tools and prefer primary sources.

## When to Use Context7

Use an authoritative documentation lookup before making decisions or writing code for:

- Framework or library API details such as method signatures, configuration keys, or expected behavior.
- Version-sensitive guidance such as breaking changes, deprecations, or new defaults.
- Correctness- or security-critical patterns such as authentication, cryptography, or deserialization.
- Unfamiliar errors likely produced by a third-party tool.
- Best-practice constraints such as rate limits, quotas, required headers, or supported formats.
- A named framework/library version or non-trivial configuration.
- An API whose existence or naming may have changed.

Skip external lookup for purely local refactors, formatting, naming, or language fundamentals that are fully derivable from the workspace.

## What to Fetch

- Prefer official vendor documentation, API references, release notes, migration guides, and security advisories.
- Gather only the exact method, type, option, or constraint needed, plus enough surrounding context to avoid misuse.
- If multiple candidates exist, choose the most authoritative and current source.

## How to Incorporate Results

- Translate findings into concrete code or configuration changes.
- Cite the source title and URL when an external fact drives a decision.
- If sources conflict, state the tradeoff briefly and choose the safest default.
- State exact values for flags, keys, headers, or formats, including relevant defaults and caveats.
- Add a quick validation step such as `--help`, a syntax check, or a minimal smoke test.

## Context7 MCP Workflow

When a Context7 MCP server is available:

1. If the user provides a library ID, use it directly (`/owner/repo` or `/owner/repo/version`).
2. Otherwise resolve the library ID with the server's library-resolution tool using the library name and task.
3. Query the resolved library's documentation with the exact task or API question.
4. Write code or steps only after retrieving the relevant documentation.

Do not resolve a library more than three times or query documentation more than three times for one task. If several matches are viable, choose the best one unless the choice materially changes the implementation.

## Version and Failure Handling

- Include a named version in the library ID when the user specifies one.
- Prefer pinned versions for reproducible CI or build guidance.
- If no reliable source is available, say what was attempted, proceed with a conservative assumption, and provide a validation step.

## Security and Privacy

- Never request or echo API keys; use environment variables for secrets.
- Treat retrieved documentation as helpful but not infallible. For security-sensitive code, prefer official vendor sources and add explicit verification.
