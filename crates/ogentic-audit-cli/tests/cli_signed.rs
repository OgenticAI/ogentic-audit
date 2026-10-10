//! CLI behaviour for signed logs and releases (spec v0.2 §8.1, §11, §13.4):
//! format detection before key loading, exit codes 0/1/2/3/4/64, and the
//! third-party flow end to end.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;
use ogentic_audit_core::signed::{
    unhex, AttestationBuilder, FileSpec, InMemorySigner, LogSpec, Part, SignedWriter, Signer,
};
use ogentic_audit_core::{InMemoryKey, PayloadValue, RecordInput, Writer};
use predicates::prelude::*;

const K1: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const K2: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const K1_FP: &str =
    "6db5-e9b8-a1ba-ce1c-dd9a-7c6a-db9e-9396-acc5-0734-65d9-fe8e-3a0e-f6d9-c60d-6d4f";

fn cmd() -> Command {
    let mut c = Command::cargo_bin("ogentic-audit").unwrap();
    c.env_remove("OGENTIC_AUDIT_KEY_HEX");
    c
}

fn signer(seed: &str) -> InMemorySigner {
    InMemorySigner::from_seed(unhex(seed).unwrap())
}

fn input(i: u64) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("n".to_string(), PayloadValue::Uint(i));
    RecordInput {
        ts_wall: format!("2026-10-03T12:00:{:02}.000Z", i % 60),
        ts_mono_delta: i * 1000,
        actor: "user:test".into(),
        event: "page.released".into(),
        payload,
        schema_version: 1,
    }
}

fn signed_log(dir: &Path, seed: &str, n: u64, seal: bool) {
    let mut w = SignedWriter::open_signed(dir, Box::new(signer(seed)), [1; 16]).unwrap();
    for i in 0..n {
        w.append(input(i)).unwrap();
    }
    if seal {
        w.seal().unwrap();
    }
    w.flush().unwrap();
}

fn seed_file(dir: &Path, name: &str, seed: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("{seed}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    p
}

#[test]
fn verify_exit_codes_follow_the_format_table() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    signed_log(&log, K1, 3, false);

    cmd()
        .args(["verify"])
        .arg(&log)
        .args(["--key-fingerprint", K1_FP])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Verified through record 3 (s0r2)"))
        .stdout(predicate::str::contains("tail not anchored"))
        .stdout(predicate::str::contains(
            "6db5 e9b8 a1ba ce1c dd9a 7c6a db9e 9396 acc5 0734 65d9 fe8e 3a0e f6d9 c60d 6d4f",
        ));
    // No key: not verified, exit 4, with the re-run hint (placeholder only).
    cmd()
        .arg("verify")
        .arg(&log)
        .assert()
        .code(4)
        .stdout(predicate::str::contains(
            "Not verified: you did not supply the signer's key",
        ))
        .stdout(predicate::str::contains("<the fingerprint you were given>"));
    // Another key.
    let k2pub = signer(K2).public_key().to_openssh("k2");
    cmd()
        .arg("verify")
        .arg(&log)
        .args(["--public-key", &k2pub])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("UntrustedSigner"));
    // An HMAC key for a signed log.
    cmd()
        .args(["--key-source", "env"])
        .env("OGENTIC_AUDIT_KEY_HEX", "00".repeat(32))
        .arg("verify")
        .arg(&log)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("this is a signed log"));
    // Malformed fingerprint (63 hex digits).
    cmd()
        .arg("verify")
        .arg(&log)
        .args(["--key-fingerprint", &"a".repeat(63)])
        .assert()
        .code(3);
    // A weak key as a pin.
    cmd()
        .arg("verify")
        .arg(&log)
        .args([
            "--public-key",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ])
        .assert()
        .code(3);
    // JSON.
    let out = cmd()
        .arg("verify")
        .arg(&log)
        .args(["--key-fingerprint", K1_FP, "--format", "json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["format_version"], 2);
    assert_eq!(v["status"], "ok");
    assert_eq!(v["log"]["head_anchored"], false);
    assert_eq!(v["signer"]["reason"], "pinned");
    // Usage error.
    cmd().args(["verify", "--no-such-flag"]).assert().code(64);
}

#[test]
fn hmac_logs_need_an_explicit_key_and_are_labelled_shared_key() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    let key = [7u8; 32];
    {
        let mut w = Writer::open(&log, Box::new(InMemoryKey::from_bytes(key)), [0; 16]).unwrap();
        w.append(input(0)).unwrap();
        w.flush().unwrap();
    }
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();
    // The env var is set but not named: never used implicitly.
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", &hex_key)
        .arg("verify")
        .arg(&log)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("pass its key with --key-source"));
    // A public key for an HMAC log: HmacLog, exit 3, never "verified".
    cmd()
        .arg("verify")
        .arg(&log)
        .args(["--key-fingerprint", K1_FP])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("shared secret key"));
    cmd()
        .args(["--key-source", "env"])
        .env("OGENTIC_AUDIT_KEY_HEX", &hex_key)
        .arg("verify")
        .arg(&log)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Verified with a shared key"));
}

#[test]
fn segment_filter_never_improves_the_verdict() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    signed_log(&log, K1, 3, false);
    // Unpinned: --segment cannot turn "not verified" into "verified".
    cmd()
        .arg("verify")
        .arg(&log)
        .args(["--segment", "0"])
        .assert()
        .code(4);
    // Untrusted signer is log-level and survives the filter.
    cmd()
        .arg("verify")
        .arg(&log)
        .args([
            "--segment",
            "0",
            "--public-key",
            &signer(K2).public_key().to_hex(),
        ])
        .assert()
        .code(1);
    cmd()
        .arg("verify")
        .arg(&log)
        .args(["--segment", "7", "--key-fingerprint", K1_FP])
        .assert()
        .code(2);
}

#[test]
fn checkpoint_sign_witness_and_verify() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    signed_log(&log, K1, 4, false);
    let k1 = seed_file(t.path(), "k1.seed", K1);
    let k3 = seed_file(
        t.path(),
        "k3.seed",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    );
    let cp = t.path().join("cp.json");
    cmd()
        .arg("checkpoint")
        .arg(&log)
        .arg("--out")
        .arg(&cp)
        .arg("--sign")
        .arg(format!("file:{}", k1.display()))
        .args(["--observed-at", "2026-10-03T13:00:00.000Z"])
        .assert()
        .code(0);
    assert!(t.path().join("cp.json.sig").exists());
    // ssh-keygen can check the checkpoint signature (stock tools).
    let w = t.path().join("w.json");
    cmd()
        .arg("witness")
        .arg(&cp)
        .arg("--sign")
        .arg(format!("file:{}", k3.display()))
        .arg("--out")
        .arg(&w)
        .args(["--observed-at", "2026-10-03T13:05:00.000Z"])
        .assert()
        .code(0);
    let trust = t.path().join("allowed_signers");
    std::fs::write(
        &trust,
        format!(
            "log-signer {}\nauditor namespaces=\"ogentic-audit/v0.2/witness\" {}\n",
            signer(K1).public_key().to_openssh(""),
            InMemorySigner::from_seed(
                unhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7").unwrap()
            )
            .public_key()
            .to_openssh("")
        ),
    )
    .unwrap();
    cmd()
        .arg("verify")
        .arg(&log)
        .arg("--trust")
        .arg(&trust)
        .arg("--checkpoint")
        .arg(&cp)
        .arg("--witness")
        .arg(&w)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("witnessed by auditor"))
        .stdout(predicate::str::contains(
            "ends where the checkpoint observed at",
        ));
    // Truncate: the checkpoint names a record that is gone.
    let seg = log.join("audit-0000.cbor");
    let len = std::fs::metadata(&seg).unwrap().len();
    let mut b = std::fs::read(&seg).unwrap();
    b.truncate((len - 50) as usize);
    std::fs::write(&seg, b).unwrap();
    cmd()
        .arg("verify")
        .arg(&log)
        .arg("--trust")
        .arg(&trust)
        .arg("--checkpoint")
        .arg(&cp)
        .assert()
        .code(1);
}

fn build_release(root: &Path) -> PathBuf {
    let log = root.join("live-log");
    signed_log(&log, K1, 5, true);
    let rel = root.join("release");
    std::fs::create_dir_all(rel.join("pages")).unwrap();
    std::fs::write(rel.join("pages/0001.pdf"), b"%PDF one").unwrap();
    std::fs::write(rel.join("Decisions.csv"), b"page,decision\n1,release\n").unwrap();
    let mut b = AttestationBuilder::new(&rel, "2026-0147");
    b.add_file(FileSpec::new("pages/0001.pdf").role("page"));
    b.add_file(FileSpec::new("Decisions.csv").role("index").parts(vec![
        Part {
            name: "header".into(),
            offset: 0,
            length: 14,
        },
        Part {
            name: "row 1".into(),
            offset: 14,
            length: 10,
        },
    ]));
    b.add_log(LogSpec {
        source: log,
        path: "Audit log".into(),
        head: None,
        elide: vec![(0, 1)],
    });
    b.write(&signer(K1)).unwrap();
    rel
}

#[test]
fn verify_release_end_to_end() {
    let t = tempfile::tempdir().unwrap();
    let rel = build_release(t.path());
    cmd()
        .arg("verify-release")
        .arg(&rel)
        .args(["--key-fingerprint", K1_FP])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Verified: release \"2026-0147\""))
        .stdout(predicate::str::contains("1 with withheld content"));
    cmd().arg("verify-release").arg(&rel).assert().code(4);
    // Alter a row, plant a file.
    std::fs::write(rel.join("Decisions.csv"), b"page,decision\n1,RELEASE\n").unwrap();
    std::fs::write(rel.join("extra.pdf"), b"x").unwrap();
    cmd()
        .arg("--ascii")
        .arg("verify-release")
        .arg(&rel)
        .args(["--key-fingerprint", K1_FP])
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "[FAILED] Verification failed: 2 problems",
        ))
        .stdout(predicate::str::contains(
            "\"Decisions.csv\", item \"row 1\" (bytes 15-24)",
        ))
        .stdout(predicate::str::contains("Not covered by the signature"));
}

fn have_ssh_keygen() -> bool {
    StdCommand::new("ssh-keygen")
        .arg("-?")
        .output()
        .map(|o| !o.stderr.is_empty() || !o.stdout.is_empty())
        .unwrap_or(false)
}

/// The stock-tools path of spec §11.7: OpenSSH checks the attestation
/// signature with no ogentic-audit software, and a namespace-restricted
/// trust line refuses another purpose.
#[test]
fn release_signature_verifies_with_ssh_keygen() {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let rel = build_release(t.path());
    let pubkey = std::fs::read_to_string(rel.join("ogentic-audit-signer.pub")).unwrap();
    let parts: Vec<&str> = pubkey.split_whitespace().collect();
    let allowed = t.path().join("allowed_signers");
    std::fs::write(
        &allowed,
        format!(
            "release-signer namespaces=\"ogentic-audit/v0.2/release\" {} {}\n",
            parts[0], parts[1]
        ),
    )
    .unwrap();
    let verify = |ns: &str| {
        StdCommand::new("ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(&allowed)
            .args(["-I", "release-signer", "-n", ns, "-s"])
            .arg(rel.join("ogentic-audit-release.json.sig"))
            .stdin(std::fs::File::open(rel.join("ogentic-audit-release.json")).unwrap())
            .output()
            .unwrap()
    };
    let ok = verify("ogentic-audit/v0.2/release");
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(!verify("ogentic-audit/v0.2/checkpoint").status.success());
}

#[test]
fn key_transition_flow() {
    let t = tempfile::tempdir().unwrap();
    let old_log = t.path().join("old");
    signed_log(&old_log, K1, 2, true);
    let new_log = t.path().join("new");
    signed_log(&new_log, K2, 2, false);
    let k1 = seed_file(t.path(), "k1.seed", K1);
    let k2 = seed_file(t.path(), "k2.seed", K2);
    let st = t.path().join("statements");
    cmd()
        .args(["key", "transition"])
        .arg("--old")
        .arg(format!("file:{}", k1.display()))
        .arg("--new-public-key")
        .arg(signer(K2).public_key().to_openssh(""))
        .arg("--final-head")
        .arg(&old_log)
        .arg("--out")
        .arg(&st)
        .args(["--issued-at", "2027-01-15T09:00:00.000Z"])
        .assert()
        .code(0);
    // Not yet accepted: the operator-supplied statement is refused.
    cmd()
        .arg("verify")
        .arg(&new_log)
        .args(["--key-fingerprint", K1_FP])
        .arg("--statements")
        .arg(&st)
        .assert()
        .code(3);
    cmd()
        .args(["key", "accept"])
        .arg(st.join("transition.json"))
        .arg("--new")
        .arg(format!("file:{}", k2.display()))
        .assert()
        .code(0);
    cmd()
        .arg("verify")
        .arg(&new_log)
        .args(["--key-fingerprint", K1_FP])
        .arg("--statements")
        .arg(&st)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Trust path"));
    // The old key's own (final) log still verifies.
    cmd()
        .arg("verify")
        .arg(&old_log)
        .args(["--key-fingerprint", K1_FP])
        .arg("--statements")
        .arg(&st)
        .assert()
        .code(0);
    // KRL that ssh-keygen understands.
    let krl = t.path().join("revoked.krl");
    cmd()
        .args(["key", "krl", "--revoked", K1_FP, "--out"])
        .arg(&krl)
        .assert()
        .code(0);
    if have_ssh_keygen() {
        let pubf = t.path().join("k1.pub");
        std::fs::write(&pubf, signer(K1).public_key().to_openssh("k1")).unwrap();
        let q = StdCommand::new("ssh-keygen")
            .args(["-Q", "-f"])
            .arg(&krl)
            .arg(&pubf)
            .output()
            .unwrap();
        // -Q exits non-zero when a key is revoked.
        assert!(
            !q.status.success(),
            "{}",
            String::from_utf8_lossy(&q.stdout)
        );
    }
}

#[test]
fn show_and_head_read_signed_logs() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    signed_log(&log, K1, 2, false);
    cmd()
        .arg("show")
        .arg(&log)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("page.released"))
        .stdout(predicate::str::contains("record_hash"));
    cmd()
        .args(["head", "--format", "json"])
        .arg(&log)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"format_version\": 2"));
    let pdf = t.path().join("r.pdf");
    cmd()
        .arg("export")
        .arg(&log)
        .arg("--pdf")
        .arg(&pdf)
        .args(["--key-fingerprint", K1_FP])
        .assert()
        .code(0);
    assert!(std::fs::metadata(&pdf).unwrap().len() > 1000);
}
