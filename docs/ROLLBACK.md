# Rollback and version recovery

Every version of this project stays recoverable. Nothing is ever overwritten,
squashed, force-pushed or rebased, so recovery is always a read, never a
repair.

All commands below are **non-destructive**. None of them discards work in your
working tree.

## What is preserved

### Annotated tags — immutable points in history

| Tag | What it holds |
|---|---|
| `archive/pre-final-redesign-2026` | Before any of the presentation work: M0–M8 complete, M9 partially executed |
| `archive/ui-redesign-v1` | The first workflow redesign |
| `archive/submission-deck-v1` | The first verified six-slide deck |
| `archive/demo-package-v1` | The first demo package and footage |
| `archive/final-master-baseline` | Before the final master polish sprint |

List them, newest first:

```bash
git tag -l 'archive/*' --sort=-creatordate
git show archive/final-master-baseline --stat | head -40
```

### Branches — the same points, as branches

`archive/pre-final-redesign` and `archive/final-master-baseline` point at the
same commits as their tags. They exist because a branch is easier to browse on
GitHub.

### Artifact archive — files, not just history

`submission/archive/` holds each superseded version as files, so you can open a
previous deck without checking anything out:

```
submission/archive/
  ppt-v1/    the deck, its PDF, every slide rendered, SHA256SUMS, CHANGELOG
  ui-v1/     the screenshot set from that UI, SHA256SUMS, CHANGELOG
  demo-v1/   the demo package, SHA256SUMS, CHANGELOG, VIDEO.md
```

Large media is deliberately **not** in Git. Video cuts live in
`local-evidence/video-archive/` (gitignored) and are recorded in Git by
filename, SHA-256, duration, resolution and source commit — see
`submission/archive/demo-v1/VIDEO.md`.

## Recovering things

### Look at an old version without changing anything

```bash
git switch --detach archive/final-master-baseline
# ...look around...
git switch -                      # back to where you were
```

### Take one file back, leaving everything else alone

```bash
git restore --source=archive/final-master-baseline -- frontend/src/index.css
```

Or, equivalently:

```bash
git checkout archive/final-master-baseline -- frontend/src/index.css
```

Both write into your working tree and stop there. Review with `git diff`, then
commit or `git restore` the file again to undo.

### Take a whole directory back

```bash
git restore --source=archive/ui-redesign-v1 -- frontend/src/
```

### Extract a file to a scratch location, touching nothing

```bash
git show archive/final-master-baseline:submission/final/SecureMailScope-SIH26159-Zero-Day.pdf \
  > /tmp/deck-v1.pdf
```

This is the safest option: it writes outside the repository entirely.

### Recover a deleted file

```bash
git log --oneline --diff-filter=D -- path/to/file    # find the deleting commit
git show <sha>^:path/to/file > path/to/file          # restore from its parent
```

### Start a branch from an old point

```bash
git switch -c experiment/from-v1 archive/final-master-baseline
```

## Verifying an archived artifact

Each `submission/archive/*/` carries `SHA256SUMS`:

```bash
cd submission/archive/ppt-v1 && shasum -a 256 -c SHA256SUMS
```

### Restore proof

Verified on 2026-09-23: the archived deck PDF was extracted from history into a
temporary directory with `git show`, and its SHA-256 matched the working copy
byte for byte. The working tree was not touched.

## What not to do

These are destructive. None of them is needed to recover anything here.

- `git reset --hard` on a branch whose work you have not otherwise saved
- `git push --force` to a published branch
- `git rebase` on commits already pushed to `main`
- deleting or re-pointing an `archive/*` tag

If a tag ever needs to change, create a new one. The old one stays.

## If the remote and local disagree

```bash
git fetch origin
git log --oneline HEAD..origin/main    # on the remote, not local
git log --oneline origin/main..HEAD    # local, not pushed
```

Resolve by merging or by pushing. Never by force.
