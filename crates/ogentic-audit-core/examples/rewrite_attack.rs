//! Runnable demonstration of the chain-rewrite attack and the
//! checkpoint that catches it.
//!
//! ```sh
//! cargo run -p ogentic-audit-core --example rewrite_attack
//! ```
//!
//! The attack is the one described in [NousResearch/hermes-agent#487]:
//! an adversary holding the HMAC key and write access truncates the log
//! at a chosen point and re-chains fabricated history forward. Every
//! internal check still passes, because the chain is only ever validated
//! against itself.
//!
//! A checkpoint — a `(segment, record_id, hmac)` triple observed earlier
//! and held somewhere the log's writer cannot reach — is what makes the
//! rewrite visible.
//!
//! [NousResearch/hermes-agent#487]: https://github.com/NousResearch/hermes-agent/issues/487

use std::collections::BTreeMap;

use ogentic_audit_core::{
    Checkpoint, InMemoryKey, KeyHandle, PayloadValue, Reader, RecordInput, Verdict, Verifier,
    VerifyOptions, Writer, HMAC_LEN,
};

const KEY: [u8; 32] = [7u8; 32];
const SESSION: [u8; 16] = [3u8; 16];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = std::env::temp_dir().join("ogentic-audit-rewrite-attack");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;

    // ---- 1. Honest history -------------------------------------------------
    // The agent did four things. The third one is the one that will
    // later be inconvenient for somebody.
    write_log(
        &tmp,
        &[
            ("vault.unlocked", "matter opened"),
            ("file.opened", "deposition.pdf"),
            (
                "llm.cloud-approved",
                "sent privileged text to a cloud model",
            ),
            ("vault.locked", "matter closed"),
        ],
    )?;

    println!("== honest log ==");
    report(&tmp, None);

    // ---- 2. Observe a checkpoint -------------------------------------------
    // This triple is the only thing that will survive the rewrite — and
    // only because it is about to be handed to someone else.
    let cp = observe(&tmp, 0, 2)?;
    println!(
        "\ncheckpoint observed: s{}r{} hmac={}…",
        cp.segment,
        cp.record_id,
        &hex(&cp.hmac)[..16]
    );
    println!("(give this to a customer, a regulator, or a public log —");
    println!(" a copy kept next to the log is worthless)");

    // ---- 3. The rewrite ----------------------------------------------------
    // The adversary has the key. They keep the first two records, erase
    // the embarrassing third, and re-chain a plausible history forward.
    std::fs::remove_dir_all(&tmp)?;
    std::fs::create_dir_all(&tmp)?;
    write_log(
        &tmp,
        &[
            ("vault.unlocked", "matter opened"),
            ("file.opened", "deposition.pdf"),
            ("file.closed", "no cloud model was ever used"),
            ("vault.locked", "matter closed"),
        ],
    )?;

    println!("\n== after the rewrite ==");
    print!("without a checkpoint: ");
    report(&tmp, None);
    print!("with the checkpoint:  ");
    report(&tmp, Some(cp));

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

fn report(dir: &std::path::Path, checkpoint: Option<Checkpoint>) {
    let verifier = Verifier::new(Box::new(InMemoryKey::from_bytes(KEY)));
    let opts = VerifyOptions {
        forensic_mode: false,
        checkpoint,
    };
    match verifier.verify_with_options(dir, opts) {
        Ok(r) => match (r.verdict, r.violation) {
            (Verdict::Verified, _) => {
                println!("VERIFIED ({} records)", r.log.records_inspected)
            },
            (Verdict::Violation, Some(v)) => {
                println!("VIOLATION {} — {}", v.kind.as_str(), v.message)
            },
            (Verdict::Violation, None) => println!("VIOLATION (unspecified)"),
        },
        Err(e) => println!("ERROR {e}"),
    }
}

fn observe(
    dir: &std::path::Path,
    segment: u16,
    record_id: u64,
) -> Result<Checkpoint, Box<dyn std::error::Error>> {
    let reader = Reader::open(dir)?;
    let mut iter = reader.iter();
    let mut hmac: Option<[u8; HMAC_LEN]> = None;
    while let Some(r) = iter.next_record()? {
        if r.segment_index == segment && r.record_id == record_id {
            hmac = Some(r.hmac);
            break;
        }
    }
    Ok(Checkpoint {
        key_id: *InMemoryKey::from_bytes(KEY).key_id().as_bytes(),
        segment,
        record_id,
        hmac: hmac.ok_or("record not found")?,
        observed_at: "2026-07-20T20:00:00Z".to_string(),
    })
}

fn write_log(
    dir: &std::path::Path,
    events: &[(&str, &str)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = Writer::open(dir, Box::new(InMemoryKey::from_bytes(KEY)), SESSION)?;
    for (i, (event, note)) in events.iter().enumerate() {
        let mut payload = BTreeMap::new();
        payload.insert("note".to_string(), PayloadValue::Text((*note).to_string()));
        writer.append(RecordInput {
            ts_wall: format!("2026-07-20T20:00:{:02}.000Z", i),
            ts_mono_delta: (i as u64) * 1000,
            actor: "user:counsel-of-record".into(),
            event: (*event).into(),
            payload,
            schema_version: 1,
        })?;
    }
    writer.flush()?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
