//! Every CLI-expressible run of `tests/vectors/v0.2` through the binary:
//! exit codes, verdicts and reasons as a third party would see them.
//! (Runs that need statements found inside a bundle are library-only and
//! are covered by `ogentic-audit-core`'s `signed_vectors` test.)

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value as J;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/v0.2")
}

/// Command-line arguments and environment for one run.
type Invocation = (Vec<String>, Vec<(String, String)>);

fn args_for(dir: &Path, r: &J) -> Option<Invocation> {
    if r.get("statements_source").and_then(J::as_str) == Some("bundle") {
        return None;
    }
    let p = |s: &str| dir.join(s).to_string_lossy().into_owned();
    let mut a: Vec<String> = Vec::new();
    let mut env = Vec::new();
    if let Some(src) = r.get("hmac_key_source").and_then(J::as_str) {
        a.extend(["--key-source".into(), src.into()]);
    }
    if let Some(e) = r.get("env").and_then(J::as_object) {
        for (k, v) in e {
            env.push((k.clone(), v.as_str().unwrap().to_string()));
        }
    }
    let cmd = r["command"].as_str().unwrap();
    match cmd {
        "verify" | "verify-release" => a.push(cmd.into()),
        "checkpoint-compare" => {
            a.extend([
                "checkpoint".into(),
                "compare".into(),
                p(r["target"].as_str().unwrap()),
                p(r["other"].as_str().unwrap()),
            ]);
            return Some((a, env));
        },
        _ => return None,
    }
    a.push(p(r["target"].as_str().unwrap()));
    if let Some(k) = r.get("public_key").and_then(J::as_str) {
        a.extend(["--public-key".into(), k.into()]);
    }
    for f in r
        .get("key_fingerprint")
        .and_then(J::as_array)
        .into_iter()
        .flatten()
    {
        a.extend(["--key-fingerprint".into(), f.as_str().unwrap().into()]);
    }
    if let Some(t) = r.get("trust").and_then(J::as_str) {
        a.extend(["--trust".into(), p(t)]);
    }
    for (flag, key) in [
        ("--statements", "statements"),
        ("--revocations", "revocations"),
        ("--checkpoint", "checkpoints"),
        ("--witness", "witnesses"),
    ] {
        for v in r.get(key).and_then(J::as_array).into_iter().flatten() {
            a.extend([flag.into(), p(v.as_str().unwrap())]);
        }
    }
    if let Some(v) = r.get("expect_log_id").and_then(J::as_str) {
        a.extend(["--expect-log-id".into(), v.into()]);
    }
    if let Some(v) = r.get("segment").and_then(J::as_u64) {
        a.extend(["--segment".into(), v.to_string()]);
    }
    if let Some(v) = r.get("expect_release_id").and_then(J::as_str) {
        a.extend(["--expect-release-id".into(), v.into()]);
    }
    if r.get("allow_unattested").and_then(J::as_bool) == Some(true) {
        a.push("--allow-unattested".into());
    }
    a.extend(["--format".into(), "json".into()]);
    Some((a, env))
}

#[test]
fn every_cli_run() {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(vectors_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    let mut n = 0;
    for dir in dirs {
        let inp: J =
            serde_json::from_str(&std::fs::read_to_string(dir.join("inputs.json")).unwrap())
                .unwrap();
        for r in inp["runs"].as_array().unwrap() {
            let Some((args, env)) = args_for(&dir, r) else {
                continue;
            };
            n += 1;
            let mut c = Command::cargo_bin("ogentic-audit").unwrap();
            c.env_remove("OGENTIC_AUDIT_KEY_HEX");
            for (k, v) in &env {
                c.env(k, v);
            }
            let out = c.args(&args).output().unwrap();
            let e = &r["expect"];
            let ctx = format!(
                "{} {:?}\nstdout={}\nstderr={}",
                dir.display(),
                args,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                out.status.code(),
                Some(e["exit"].as_i64().unwrap() as i32),
                "exit: {ctx}"
            );
            if r["command"] == "checkpoint-compare" {
                continue;
            }
            if out.status.code() == Some(3) || out.status.code() == Some(2) {
                if let Some(kind) = e.get("error").and_then(J::as_str) {
                    let needle = match kind {
                        "HmacLog" => "shared secret key",
                        other => other,
                    };
                    assert!(
                        String::from_utf8_lossy(&out.stderr).contains(needle),
                        "error {kind}: {ctx}"
                    );
                }
                continue;
            }
            let v: J =
                serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("not JSON: {ctx}"));
            if let Some(want) = e.get("authentication").and_then(J::as_str) {
                assert_eq!(v["authentication"], want, "{ctx}");
                continue;
            }
            let verdict = v["verdict"].as_str().unwrap_or_default();
            let first = if v.get("violation").is_some() {
                v["violation"].clone()
            } else {
                v["violations"].get(0).cloned().unwrap_or(J::Null)
            };
            let compact = match verdict {
                "Verified" | "SelfConsistent" => verdict.to_string(),
                _ => match (
                    first["kind"].as_str(),
                    first["location"]["item"].as_str(),
                    first["item"].as_str(),
                ) {
                    (Some(k), Some(item), _) => format!("{k}@{item}"),
                    (Some(k), None, Some(item)) => format!("{k}@{item}"),
                    _ => "Violation".into(),
                },
            };
            if let Some(want) = e.get("verdict").and_then(J::as_str) {
                assert_eq!(compact, want, "verdict: {ctx}");
            }
            if let Some(want) = e.get("reason").and_then(J::as_str) {
                let got = first["reason"].as_str().or(v["reason"].as_str());
                assert_eq!(got, Some(want), "reason: {ctx}");
            }
        }
    }
    assert!(n >= 100, "only {n} CLI runs");
}
