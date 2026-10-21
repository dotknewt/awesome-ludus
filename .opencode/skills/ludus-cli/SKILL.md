---
name: ludus-cli
description: Provide Ludus CLI command guidance, flags, and workflows for range lifecycle, template management, testing mode, snapshots, users/groups, and diagnostics. Use when users ask how to run, interpret, or troubleshoot any `ludus` command.
---

# Ludus CLI Reference

Reference for Ludus CLI command syntax, flags, and workflows. Use this when users need to run CLI commands directly or when the Ludus API is unavailable.

## Key Concepts

### Command Pattern
```
ludus COMMAND [SUBCOMMAND] [ARGS] [--FLAGS]
```

### Global Flags (Available on All Commands)
- `--json` - Format output as JSON
- `--url string` - Server URL (default: `https://198.51.100.1:8080`)
- `-u, --user string` - Impersonate user (admin only)
- `-r, --range string` - Target range ID
- `--proxy string` - HTTP(S) proxy URL
- `--verbose` - Verbose output
- `--verify` - Verify HTTPS certificate

All flags can be set via environment variables: `LUDUS_FLAG_NAME` (uppercase).

### Common Workflows

**Initial Setup:**
```bash
ludus apikey                    # Store API key
ludus templates list            # Check available templates
ludus range config get example  # Get example config
```

**Deploy a Range:**
```bash
ludus range config set -f config.yml  # Set config
ludus range deploy                     # Full deploy
ludus range logs -f                    # Watch progress
ludus range status                     # Check status
```

For changed role work, run `ansible-validation` when finishing the work, scoped to changed role files and changed declared dependencies only, as specified in [Ludus authoring policy](../../../docs/instructions/ludus-authoring.md#verification-and-evidence). This check is not a prerequisite for live deployment or retries. An explicit live/deploy request with a range and scope, or `/live` with both arguments, authorizes that requested cycle; do not ask for duplicate approval. Follow [live-debugging.md](../../../docs/instructions/live-debugging.md) for the cycle and its scope boundaries. Report any static validation separately from live evidence; static results do not establish runtime behavior or authorize actions outside the requested scope.

**Testing Mode:**
```bash
ludus testing start                      # Snapshot + block internet
ludus testing allow -d example.com       # Allow a domain
ludus testing stop                       # Revert snapshots + restore internet
```

**Template Management:**
```bash
ludus templates add -d ./my-template   # Add template
ludus templates build                   # Build all unbuilt
ludus templates build -n name1,name2   # Build specific
ludus templates logs -f                 # Watch build progress
```

## References

- Use `references/commands.md` for the complete command reference with subcommands, flags, and examples.
- Use `https://docs.ludus.cloud/docs/cli` as the authoritative source for CLI behavior and changes.
