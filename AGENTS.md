# AGENTS.md

## Version bump & release process

When a feature or change is finished — **before pushing** — bump the version,
tag it, then push. Pushing a `v*` tag triggers `.github/workflows/release.yml`,
which builds all release binaries and publishes the GitHub Release.

1. **Bump semver** in `Cargo.toml` (the `version` field — `Cargo.lock` updates
   automatically when you run `cargo check`, never edit it by hand) and add a
   matching `## vX.Y.Z` entry at the top of `CHANGELOG.md`:
   - `major` — breaking changes (protocol changes, removed flags, incompatible behavior)
   - `minor` — new features (the usual case)
   - `patch` — bug fixes
2. **Sanity check**: `cargo check`
3. **Commit** the feature + version bump + changelog.
4. **Push** the commit, then **push the tag** `v<version>`. The tag version
   must match the version in `Cargo.toml`.

### Exact commands

```bash
# 1. edit Cargo.toml (version field) + CHANGELOG.md (bump to X.Y.Z);
#    Cargo.lock updates itself when you run:
cargo check

# 2. commit
git add -A
git commit -m "feat: <short summary> (vX.Y.Z)"

# 3. push commit, then tag + push tag
git push origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

Example: `v3.1.0` — minor bump for cross-platform `ww-target`.

## Platform constraints

- `ww` and `ww-server` are Unix-only by design (non-Unix builds fail at
  compile time with a `compile_error!`). Never build them for Windows.
- `ww-target` is cross-platform (Linux, macOS, Windows).
