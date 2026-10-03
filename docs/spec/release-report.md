# ogentic-audit — Release report shape

**Status:** Normative (companion to [`v0.2.md`](v0.2.md) §11.6)

`ogentic-audit verify-release --format json` and `python -m ogentic_audit verify-release --format json` print one report per release folder. Unlike a log report, a release report lists **every** problem, because a release's items are independent.

```json
{
  "format": "ogentic-audit-release-report/v1",
  "verdict": "Violation",
  "status": "tampered",
  "reason": null,
  "release_id": "2026-0147",
  "attestation_sha256": "<64-hex>",
  "signer": { "principal": null, "alg": "ed25519", "key_id_hex": "<64-hex>",
              "fingerprint_grouped": "6db5 e9b8 … 6d4f", "fingerprint_openssh": "SHA256:…",
              "trusted": true, "trust_path": ["<64-hex>"], "reason": "pinned" },
  "files": { "attested": 5, "verified": 4, "unattested": [], "ignored": [] },
  "logs": [
    { "path": "Audit log", "head_anchored": true, "records_after_head": 0, "elided_records": 0,
      "report": { "format_version": 2, "…": "a log report, see violation-report.md" } }
  ],
  "violations": [
    { "item": "file:Decisions.csv#row 1", "kind": "FileAltered", "reason": "part",
      "evidence": { "expected_sha256": "<64-hex>", "actual_sha256": "<64-hex>",
                    "expected_size": 34, "actual_size": 34,
                    "part": { "name": "row 1", "offset": 14, "length": 10 } },
      "message": "item \"row 1\" (bytes 15–24) changed" }
  ],
  "warnings": [],
  "witnesses": []
}
```

| Member | Content |
|--------|---------|
| `format` | `"ogentic-audit-release-report/v1"` |
| `verdict`, `status`, `reason` | As in a log report: `Verified`/`ok` (exit 0), `SelfConsistent`/`unpinned` (exit 4, no key supplied), `Violation`/`tampered` (exit 1) |
| `release_id` | From the attestation, with control, bidirectional and invisible characters escaped as `\u{XXXX}` |
| `attestation_sha256` | SHA-256 of `ogentic-audit-release.json`: the value key statements name in `final_releases` and `trusted_releases` |
| `signer` | The attestation signer, as in a log report |
| `files` | `attested` (listed), `verified` (matched), `unattested` (present but not covered by the signature), `ignored` (operating-system litter: `.DS_Store`, `Thumbs.db`, `desktop.ini`, `._*`, `__MACOSX/`, `.Spotlight-V100/`, `.Trashes/`) |
| `logs` | Per bundled log: its log report, whether its head is anchored (the attested head), records after that head, records with withheld content |
| `violations` | Every problem, in spec §11.4 order (attestation, files, logs, unattested files) |
| `warnings` | `{item, kind, message}`: `UnattestedFile` (with `--allow-unattested`), `TornTailAfterHead`, `IgnoredStatement`, `IgnoredWitness`, and log warnings prefixed `log:<path>/` |
| `witnesses` | Valid witness co-signatures found: `{principal, key_id_hex, observed_at, checkpoint_sha256}` |

## `item`

| Item | Names |
|------|-------|
| `attestation` | The attestation or its signature |
| `file:<path>` | A released file |
| `file:<path>#<part>` | A named part (for example a row of an index) of a released file |
| `log:<path>` | A bundled log as a whole |
| `log:<path>/s<N>` / `log:<path>/s<N>r<P>` | A segment or record of a bundled log |
| `key:<64-hex>` | A key (for example `TransitionEquivocation`) |

Every name taken from the bundle is escaped as above.

## Kinds

| Kind | `reason` | Item | Meaning |
|------|----------|------|---------|
| `AttestationMissing` | | `attestation` | No `ogentic-audit-release.json` |
| `SignatureInvalid` | `missing`, `malformed`, `namespace`, `hash_alg`, `key_type`, `mismatch`, `reencoded`, `weak_key` | `attestation` | The signature file is absent, malformed, made for another purpose or with `sha256`, or does not match |
| `UntrustedSigner` | `not_trusted`, `out_of_scope` | `attestation` | Signed by a key other than the one supplied, or one not trusted to sign releases |
| `RevokedKey`, `RetiredKey` | | `attestation` | Signed by a revoked or retired key, and this release is not among those its statements still vouch for |
| `AttestationMalformed` | | `attestation` | Not canonical JSON, a float or duplicate key, a forbidden character or path, or over a size limit |
| `KeyIdMismatch` | | `attestation` | The attestation names a different key than the one that signed it |
| `ReleaseIdMismatch` | | `attestation` | Not the release given with `--expect-release-id` |
| `FileMissing` | | `file:` / `log:` | An attested file or log folder is absent |
| `FileAltered` | `size`, `part`, `outside_parts`, `content`, `not_regular_file`, `ambiguous_name` | `file:` | The file changed: its length; a named part (the item names it); bytes outside any named part; or, for a file without parts, its content. A link or special file, or a name that collides after Unicode normalization or case folding, fails closed |
| `UnattestedFile` | | `file:` | A file the attestation does not cover |
| `FormatDowngrade` | | `log:<path>/s0` | The attestation names a signed log, but this log is protected only by a shared secret key |
| any log kind | | `log:<path>/…` | From verifying a bundled log, including `CheckpointTruncated` / `CheckpointMismatch` against the attested head |

A failure at the attestation stops the run: comparing files against an attestation that is not authenticated proves nothing. Every other item is checked and reported.

`evidence` for `FileAltered`: `expected_sha256`, `actual_sha256`, `expected_size`, `actual_size`, and `part` (`{name, offset, length}`, 0-based) or null. Human output shows byte ranges 1-based and inclusive.
