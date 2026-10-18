# Source Role Discovery and Blueprint Dependencies

Gather read-only evidence before changing repository or server state.

1. **Repository contents:** Verify the role has a standard layout (`tasks/main.yml`, metadata where present). For submodules, compare `.gitmodules`, `git ls-files --stage`, the committed gitlink (mode `160000`), and `git submodule status`; a directory or `.gitmodules` entry alone does not prove the role is committed.
2. **Role identity:** Compare the directory name with `galaxy_info` in `meta/main.yml` and the server's reported identity. Check for copied `role_name` values and duplicate Galaxy identities across roles; a discovered role can appear under another role's name.
3. **Server catalog:** Use `ludus-cli` and installed CLI help to find read-only source catalog and installed-role JSON commands. Match descriptions and paths where exposed, not names alone. Record source URL/ref and sync time; distinguish a missing catalog entry from an installed-role listing mismatch.
4. **Dependency resolution:** Compare blueprint `requirements.yml` with bundled `ansible/roles/`. Determine whether the failing entry is being fetched from Galaxy or registered locally. Before removing an external requirement, verify that the bundled role is discovered and available to the target user.
5. **Version and freshness:** Record client/server versions and verify resolver behavior against that version; upstream `main` is not proof of installed behavior. Normalize commit and sync timestamps to UTC before comparing them, and prefer the server's checked-out revision when available. Local remote-tracking refs alone do not prove the server has the same commit.

Confirm recovery by checking both catalog identity and installed-role availability after an approved correction.
