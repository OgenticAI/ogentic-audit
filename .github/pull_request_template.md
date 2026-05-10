<!--
Title format: <type>(OGE-XXX): short summary
  e.g. feat(OGE-429): writer atomic flush + fsync

Allowed types: feat, fix, docs, refactor, test, chore, perf, build, ci, revert
Conventional Commits is enforced — see .commitlintrc.json.

Sign your commits (-S) and sign off (-s). Both are required to merge into main.
-->

Fixes [OGE-XXX](https://linear.app/ogenticai/issue/OGE-XXX). <!-- one line on where this stands -->

## What changed

<!-- The user-visible diff. What does a reader of the changelog need to know? -->

## How it works

<!-- The implementation. Mention any non-obvious invariant, locking, or ordering. -->

## Files

<!-- Group by area. Skip if the file list is small and self-explanatory. -->

## Format / spec impact

<!--
Does this change the on-disk format or what the verifier accepts?
  - [ ] No format change.
  - [ ] Format change — linked ADR: <link>, spec update: <link>.
If you check the second box, the ADR + spec must land before this PR's review.
-->

## Verified locally

- [ ] `cargo build --workspace`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] `maturin develop && pytest python/tests` (if Python bindings touched)
- [ ] Cross-language golden vectors still match (if writer/reader/verifier touched)

## Security checklist

- [ ] No new `unsafe` blocks (or each new block has a `// SAFETY:` comment).
- [ ] No new dependency on a non-audited crypto crate.
- [ ] HMAC key material does not leave `KeyHandle` in plaintext.
- [ ] No `SystemTime::now()` outside the `time` module (see `clippy.toml`).

## Reviewer notes

<!-- Anything the reviewer should look at first, or known follow-ups deferred to a separate ticket. -->
