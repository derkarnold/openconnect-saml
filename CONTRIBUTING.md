# Contributing to openconnect-saml

Thanks for being here. This is a small project run by one maintainer
plus drive-by contributors; the conventions below exist to keep that
sustainable, not to gate-keep.

## Quick start

```bash
git clone https://github.com/mschabhuettl/openconnect-saml.git
cd openconnect-saml
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,gui,chrome,fido2,tui]'
```

Run the test suite + lint before pushing:

```bash
.venv/bin/pytest -q --no-header
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Or — for the lint half — install the pre-commit hooks once and let
them run on every `git commit`:

```bash
pip install pre-commit
pre-commit install                  # one-off per checkout
pre-commit run --all-files          # one-off across whole tree (e.g. after pull)
```

The hook config (`.pre-commit-config.yaml`) runs the same `ruff
check --fix` and `ruff format` that CI checks, plus
trailing-whitespace / EOL / merge-conflict-marker hygiene. If a
hook auto-fixes something, `git add` the result and re-commit.

Everything green? Push. CI re-runs the same matrix on
`ubuntu-latest, 3.10/3.11/3.12/3.13` plus `windows-latest, 3.12`
(see `.github/workflows/test.yml`).

## How to file a useful issue

Please include:

1. **What you ran** — the exact CLI invocation, with secrets redacted.
2. **What happened vs what you expected** — short.
3. **Debug log** — re-run with `--log-level DEBUG`, paste the
   relevant section. For Qt-browser issues, the more verbose
   QtWebEngine-internal log is `QTWEBENGINE_CHROMIUM_FLAGS="--enable-logging=stderr --v=1"`.
4. **Environment** — distro / kernel, Python version, output of
   `pip show openconnect-saml pyqt6 pyqt6-webengine`.

The single best thing you can do to make a bug report actionable is
paste enough log that we can identify the failing step without
rerunning ourselves. Templates are at
[`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) (if present).

## How to send a useful PR

- **Branch from `main`** as `<topic>/<short-name>` (e.g.
  `fix/totp-keyring-purge`, `feat/okta-scripted-login`).
- **Tests** — if you change behaviour, add a test that would have
  failed before your change. We won't merge a behaviour change
  with no test unless you explain why one isn't possible.
- **Lint** — `ruff check .` + `ruff format .` clean.
- **CHANGELOG** — add an entry under `## [Unreleased]` describing
  the user-visible change in 1–3 sentences. Skip for pure-internal
  refactors.
- **Commit messages** — short imperative subject ("fix: hoist
  --no-cert-check from openconnect_args"), longer body if the why
  is non-obvious.
- **Don't bump the version** in `pyproject.toml` or tag a release.
  The maintainer batches releases per [Plan A](#release-policy)
  below.
- **Maintainer-edits-allowed** — please leave the box checked when
  opening the PR. It lets the maintainer push fixup commits
  (formatting, CHANGELOG entries, small style tweaks) without
  blocking on you.

The CI workflow can't run on first-time-contributor PRs without a
maintainer approval click; that's a GitHub default, not a slight.

## Release policy (for the maintainer)

**Plan A** (current): main + tags. Tag = release. No long-lived
release branches. Tag pushes fire `release.yml` and `publish.yml`,
which re-run the full test matrix from `test.yml` as a `tests` gate
job — the build / publish-to-PyPI / GitHub-release / AUR-update
jobs only run if every matrix entry (including `windows-latest`)
is green on the tagged commit.

That gate has caught Windows-only flakes between v0.22.2 and v0.22.4.
Treat a failing Windows job exactly the same as a failing Linux job —
do not ship.

If you ever need to backport to v0.22.x after main has moved to
v0.23+: branch from the `v0.22.5` tag at that moment, fix, tag the
patch (`v0.22.6`), push the tag, delete the temporary branch. No
standing per-version branches.

## Release flow (manual)

```sh
# Once CI is green on main:
git checkout main
git pull
# bump pyproject.toml + finalize CHANGELOG entry
git commit -am "release: vX.Y.Z — <summary>"
git push origin main
git tag -a vX.Y.Z -m "..."
git push origin vX.Y.Z          # this fires release / publish / AUR
```

The tag push fires `release.yml` and `publish.yml`. Both re-run the
test matrix as a `tests` gate job; build/publish/AUR only run if the
gate is green. So a Windows-only failure on the tagged commit will
hold the release back even if you forgot to check.

## What's nice to know about the codebase

- **`openconnect_saml/cli.py`** is the entry point. Subcommand-style
  parser (`connect`, `profiles`, `sessions`, `config`, `groups`,
  `history`, `service`, `setup`, `tui`, `gui`, `doctor`, …) plus a
  legacy `-s SERVER`-style top-level parser kept for backwards
  compatibility.
- **`openconnect_saml/app.py`** orchestrates a connect: loads config,
  resolves credentials + TOTP provider, dispatches to the right
  browser backend, then `subprocess.Popen`s `openconnect` itself.
- **`openconnect_saml/authenticator.py`** speaks the AnyConnect
  config-auth XML protocol against the Cisco gateway. Wraps both
  the GUI browser flows and the headless one.
- **`openconnect_saml/headless.py`** is the no-browser scripted
  authenticator. Handles generic SAML form-flows, Microsoft Entra
  ID specifically (`_auto_authenticate_entra`), and the local
  callback-server fallback.
- **`openconnect_saml/browser/`** holds the Qt (`webengine_process.py`)
  and Chrome/Playwright (`chrome.py`) backends. Both spawned in a
  child process so a browser crash doesn't take the wrapper down.
- **`tests/integration/`** drives the real CLI through a mock
  AnyConnect gateway over HTTPS. Skipped on Windows (long-lived
  subprocess + sockets flake on the GHA runner; unit tests still run).

## Code of conduct

By participating you agree to follow our
[Code of Conduct](CODE_OF_CONDUCT.md). It's the standard
Contributor Covenant; in practice: be kind, be specific, don't
expect free support to be infinite.

## Security

If you find a security issue, please **don't** open a public issue.
Email the maintainer directly (handle on the GitHub profile) or use
GitHub's "Report a vulnerability" workflow on the repo. We'll
credit reporters in the CHANGELOG once a fix is out.
