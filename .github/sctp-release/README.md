# Automated Go+SCTP releases

`.github/workflows/sctp-release.yml` cuts a Go toolchain release with SCTP
in package `net` every time upstream Go ships a release.

## What a run does

1. **Detect** (GitHub-hosted, daily at 04:23 UTC). Lists upstream `go1.N.M`
   tags, keeps the newest patch of every minor version from `MIN_MINOR` on,
   and drops those that already have a `go1.N.M-sctp.K` tag here or an open
   `sctp-release-blocked` issue. Betas and release candidates never match.
2. **Port** (`port.sh`). Rebases the SCTP series onto the upstream tag into
   `release/sctp-go1.N`:
   - a new minor version is ported from `SCTP_DEV_BRANCH` (everything after
     its merge base with upstream `master`);
   - a point release rebases the existing release branch from the previous
     patch tag onto the new one;
   - `api/next/*.txt` is folded into `api/go1.N.txt` and `doc/next` moved to
     `doc/sctp/release-notes`, because release toolchains ignore `next`.
3. **Build and test** (`build.sh`, self-hosted `[self-hosted, linux, sctp]`).
   `make.bash -distpack` with `VERSION` set to the release tag, SCTP `net`
   tests with and without `-race`, cross-GOOS build and vet, `cmd/api -check`,
   the Go/C++ interop matrix. `full_suite` adds `run.bash`.
4. **Publish** (`publish.sh`). Tags `go1.N.M-sctp.K`, pushes the release
   branch and tag, and creates a GitHub Release with
   `go1.N.M-sctp.K.linux-amd64.tar.gz`, cross-compiled
   `darwin-arm64` (macOS on Apple Silicon, where SCTP calls return
   `errors.ErrUnsupported`) and `linux-arm64` (64-bit Raspberry Pi OS)
   tarballs, the source tarball and `SHA256SUMS`.

A conflict or a red test opens an issue titled `SCTP release blocked: go1.N.M`
(`report-failure.sh`) and publishes nothing. The daily run skips that version
while the issue is open.

## One-time setup

- Repository secret `SCTP_RELEASE_TOKEN`: a fine-grained token for this
  repository with **Contents: read and write** and **Workflows: read and
  write**. The default `GITHUB_TOKEN` cannot push the rebased release
  branches because they carry `.github/workflows` changes.
- A runner with labels `self-hosted, linux, sctp`, SCTP kernel support,
  `cmake`, `g++`, `gh` and about 20 GB free.

## Manual runs

Actions → SCTP release → Run workflow:

- `version`: one upstream tag, e.g. `go1.27.4`. A second run for the same tag
  produces `-sctp.2`, `-sctp.3`, ...
- `from_dev`: port from `SCTP_DEV_BRANCH` again, to ship SCTP changes made
  since the last release of that line.
- `dry_run`: build and test without pushing or publishing.

## When a port conflicts

```sh
git fetch origin && git fetch https://github.com/golang/go tag go1.N.M
git checkout -B release/sctp-go1.N origin/release/sctp-go1.N   # or origin/sctp/go1.28 for a new line
git rebase --onto go1.N.M <old base>    # fix conflicts, git rebase --continue
git push -f origin release/sctp-go1.N
```

Then close the issue; the next run builds from the fixed branch.
