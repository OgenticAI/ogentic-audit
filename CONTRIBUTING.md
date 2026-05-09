# Contributing to ogentic-audit

Thanks for your interest in contributing. This is an Apache-2.0 licensed project; by submitting a contribution you agree to license your work under the same terms.

## Ground rules

- **Be kind.** See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- **Security issues do not go in public issues.** See [`SECURITY.md`](SECURITY.md).
- **The on-disk format is the contract.** Any change that alters byte-level output of the writer or what the verifier accepts requires an ADR and a spec update before code review.
- **Tests are not optional.** New functionality lands with property-based tests, golden vectors, or both. The library is sold on tamper-evidence — tests are the proof.

## Project layout

```
crates/
  ogentic-audit-core/        Rust library: writer, reader, verifier, key handle
  ogentic-audit-cli/         ogentic-audit CLI binary
  ogentic-audit-keychain/    Optional OS-keychain key source
python/
  ogentic-audit-py/          PyO3 binding crate
  ogentic_audit/             Python source package
docs/
  spec/                      On-disk format spec (v0.x)
  security/                  Threat model + court-defensibility brief
tests/
  vectors/                   Cross-language golden test vectors
```

## Development

Prerequisites:

- Rust stable (see `rust-toolchain.toml` once published) and `rustfmt` + `clippy`
- Python 3.9+ for the bindings
- [`maturin`](https://www.maturin.rs/) for building the Python wheel locally

Common commands:

```sh
cargo build --workspace
cargo test  --workspace --all-features
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Build + install Python bindings into the active venv
maturin develop --release
pytest python/tests
```

## Branching and commits

- Branch off `main`. Naming follows Linear: `david/oge-XXX-short-slug` for tracked work.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/). Types we use: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `build`, `ci`. Tie a commit to its Linear ticket where applicable: `feat(OGE-XXX): short summary`.
- Sign your commits (`git commit -S`). The `main` branch requires signed commits.

## Pull requests

- Open against `main`. The PR template covers the required sections — fill all of them.
- Required for merge: green CI, one approving review, signed commits, and a passing DCO check (sign off with `git commit -s`).
- Do not merge your own PRs unless explicitly authorized for that change.

## Reporting bugs

Use the issue templates under `.github/ISSUE_TEMPLATE/`. For tamper-evidence or HMAC-related findings, follow [`SECURITY.md`](SECURITY.md) instead — do not open a public issue.
