//! Third-party verification, end to end (spec v0.2).
//!
//! A producer answers a records request: it keeps a signed audit log
//! while it reviews pages, releases some, withholds one, and signs a
//! release folder. A third party (a requester, an auditor, a court) then
//! checks the folder with nothing but the producer's published key
//! fingerprint: no secret, and no copy of the producer's software beyond
//! a verifier.
//!
//! ```sh
//! cargo run -p ogentic-audit-core --example third_party_verification -- /tmp/walkthrough
//! ```
//!
//! The program writes `/tmp/walkthrough/release/` (what the requester
//! receives) and `/tmp/walkthrough/published-fingerprint.txt` (what the
//! producer publishes out of band), verifies the release as the third
//! party would, then shows what a changed row and a re-signed forgery
//! look like. `examples/third-party-verification/README.md` walks through
//! the same release with the command-line verifier and with stock tools
//! (OpenSSH and Python) only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ogentic_audit_core::signed::{
    commitment, random_nonce, verify_release, AttestationBuilder, FileSpec, Fingerprint,
    InMemorySigner, LogSpec, Part, ReleaseOptions, Scope, SignedWriter, Signer, TrustContext,
};
use ogentic_audit_core::{PayloadValue, RecordInput};

fn record(i: u64, event: &str, payload: &[(&str, PayloadValue)]) -> RecordInput {
    RecordInput {
        ts_wall: format!("2026-10-03T09:{:02}:00.000Z", i),
        ts_mono_delta: i * 60_000,
        actor: "user:reviewer".into(),
        event: event.into(),
        payload: payload
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
        schema_version: 1,
    }
}

fn text(s: &str) -> PayloadValue {
    PayloadValue::Text(s.into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args().nth(1).map_or_else(
        || std::env::temp_dir().join("ogentic-audit-walkthrough"),
        PathBuf::from,
    );
    if out.exists() {
        std::fs::remove_dir_all(&out)?;
    }
    std::fs::create_dir_all(&out)?;

    // ---------------------------------------------------------------
    // The producer.
    // ---------------------------------------------------------------
    // In production the key lives in the OS keychain
    // (ogentic_audit_keychain::KeychainSigner); here it is in memory.
    let signer = InMemorySigner::generate();
    let fingerprint = signer.public_key().fingerprint();
    // Publish the fingerprint OUT OF BAND: a website, a letter, a filing.
    std::fs::write(
        out.join("published-fingerprint.txt"),
        format!("{}\n", fingerprint.to_grouped_hex()),
    )?;

    let pages: [&[u8]; 3] = [
        b"%PDF-1.7\n% page 1: released\n",
        b"%PDF-1.7\n% page 2: released\n",
        b"%PDF-1.7\n% page 3: withheld\n",
    ];
    // The audit log. A value derived from a page that may be withheld is
    // a salted commitment, never a plain hash (a plain hash of a short or
    // templated page lets anyone confirm a guess).
    let log_dir = out.join("producer-log");
    let mut w = SignedWriter::open_signed(&log_dir, Box::new(signer_clone(&signer)), [7u8; 16])?;
    w.append(record(
        0,
        "request.received",
        &[("request", text("R-0001"))],
    ))?;
    let mut withheld_position = None;
    for (i, page) in pages.iter().enumerate() {
        let nonce = random_nonce();
        let c = commitment(&nonce, page);
        let n = i as u64 + 1;
        let decision = if i == 2 { "withhold" } else { "release" };
        let rid = w.append(record(
            n,
            "page.reviewed",
            &[
                ("page", PayloadValue::Uint(n)),
                ("decision", text(decision)),
                ("content_commitment", PayloadValue::Bytes(c.to_vec())),
            ],
        ))?;
        if i == 2 {
            // The record about the withheld page is released without its
            // body: the chain and every signature still verify.
            withheld_position = Some((w.segment_index(), rid));
        }
    }
    w.append(record(
        5,
        "release.prepared",
        &[("pages_released", PayloadValue::Uint(2))],
    ))?;
    w.seal()?;
    drop(w);

    // The release folder the requester receives.
    let rel = out.join("release");
    std::fs::create_dir_all(rel.join("pages"))?;
    std::fs::write(rel.join("pages/0001.pdf"), pages[0])?;
    std::fs::write(rel.join("pages/0002.pdf"), pages[1])?;
    // The decision index: one named part per row, so a changed row is named.
    let rows = [
        "page,decision,exemption\n",
        "1,release,\n",
        "2,release,\n",
        "3,withhold,personal privacy\n",
    ];
    std::fs::write(rel.join("Decisions.csv"), rows.concat())?;
    let mut parts = Vec::new();
    let mut offset = 0u64;
    for (i, r) in rows.iter().enumerate() {
        let name = if i == 0 {
            "header".to_string()
        } else {
            format!("row {i}")
        };
        parts.push(Part {
            name,
            offset,
            length: r.len() as u64,
        });
        offset += r.len() as u64;
    }
    let mut builder = AttestationBuilder::new(&rel, "R-0001");
    builder.add_file(FileSpec::new("pages/0001.pdf").role("page"));
    builder.add_file(FileSpec::new("pages/0002.pdf").role("page"));
    builder.add_file(FileSpec::new("Decisions.csv").role("index").parts(parts));
    builder.add_log(LogSpec {
        source: log_dir,
        path: "Audit log".into(),
        head: None,
        elide: withheld_position.into_iter().collect(),
    });
    let digest = builder.write(&signer)?;
    println!(
        "Producer: signed release R-0001 (attestation sha256 {})",
        digest.to_hex()
    );
    println!(
        "Producer: published fingerprint {}\n",
        fingerprint.to_grouped_hex()
    );

    // ---------------------------------------------------------------
    // The third party: only the release and the published fingerprint.
    // ---------------------------------------------------------------
    let published = std::fs::read_to_string(out.join("published-fingerprint.txt"))?;
    let trust = third_party_trust(&published)?;
    let report = verify_release(&rel, &trust, &ReleaseOptions::new())?;
    println!(
        "Third party, untouched release:\n{}",
        report.render_human(false, "ogentic-audit")
    );

    // A changed row of the decision index is named.
    let altered = copy_dir(&rel, &out.join("altered"))?;
    let csv = std::fs::read_to_string(altered.join("Decisions.csv"))?;
    std::fs::write(
        altered.join("Decisions.csv"),
        csv.replace("3,withhold,", "3,WITHHOLD,"),
    )?;
    let report = verify_release(&altered, &trust, &ReleaseOptions::new())?;
    println!(
        "Third party, one row changed:\n{}",
        report.render_human(false, "ogentic-audit")
    );

    // A forgery: someone changes a page and re-signs everything with
    // their own key, replacing the public key file in the folder. The
    // pinned fingerprint is what catches it.
    let forged = copy_dir(&rel, &out.join("forged"))?;
    std::fs::write(
        forged.join("pages/0002.pdf"),
        b"%PDF-1.7\n% a different page\n",
    )?;
    let mut b = AttestationBuilder::new(&forged, "R-0001");
    b.add_file(FileSpec::new("pages/0001.pdf").role("page"));
    b.add_file(FileSpec::new("pages/0002.pdf").role("page"));
    b.add_file(FileSpec::new("Decisions.csv").role("index"));
    let attacker = InMemorySigner::generate();
    let _ = std::fs::remove_dir_all(forged.join("Audit log"));
    b.write(&attacker)?;
    let report = verify_release(&forged, &trust, &ReleaseOptions::new())?;
    println!(
        "Third party, re-signed by someone else:\n{}",
        report.render_human(false, "ogentic-audit")
    );

    println!("Now try the command-line verifier and the stock-tools check:");
    println!(
        "  ogentic-audit verify-release {} --key-fingerprint \"{}\"",
        rel.display(),
        published.trim()
    );
    println!("  (see examples/third-party-verification/README.md)");
    Ok(())
}

/// What the third party trusts: the fingerprint it obtained from the
/// producer, never anything inside the release.
fn third_party_trust(published: &str) -> Result<TrustContext, Box<dyn std::error::Error>> {
    let mut t = TrustContext::new();
    t.pin_fingerprint(
        Fingerprint::parse(published)?,
        Some("producer"),
        Scope::DEFAULT,
    )?;
    Ok(t)
}

fn signer_clone(s: &InMemorySigner) -> InMemorySigner {
    InMemorySigner::from_seed(*s.seed())
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let dest = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &dest)?;
        } else {
            std::fs::copy(e.path(), dest)?;
        }
    }
    Ok(to.to_path_buf())
}
