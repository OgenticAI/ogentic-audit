//! Signed mode (format 0x0002) bindings: signing keys, signed
//! verification with pinned keys, releases, checkpoints v2.
//!
//! The Python wrapper in `ogentic_audit/__init__.py` decides between
//! HMAC and signed verification by reading the log's format first
//! (spec v0.2 §8.1); these functions are the signed half.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ogentic_audit_core::signed::json::Value;
use ogentic_audit_core::signed::{
    self as s, AttestationBuilder, FileSpec, InMemorySigner, LogSpec, Part, PublicKey,
    ReleaseOptions, Scope, SignError, Signature, SignedVerifier, SignedVerifyOptions, Signer,
    SuppliedCheckpoint, TrustContext,
};
use ogentic_audit_core::Verdict;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3::IntoPyObjectExt;

use crate::errors::{signed_violation_exception, ArgumentError, IoFailure, SignerNotPinnedError};

type PyObject = Py<PyAny>;

/// Shared handle so one key can sign through several writers.
#[derive(Clone)]
pub struct SharedSigner(pub Arc<dyn Signer>);

impl Signer for SharedSigner {
    fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }
    fn sign(&self, namespace: &str, message: &[u8]) -> Result<Signature, SignError> {
        self.0.sign(namespace, message)
    }
}

/// An Ed25519 signing key. The private key never leaves this object.
#[pyclass(name = "SigningKey", module = "ogentic_audit._native", frozen)]
pub struct PySigningKey {
    pub inner: SharedSigner,
}

#[pymethods]
impl PySigningKey {
    /// A fresh key from the OS random source (held in memory only).
    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: SharedSigner(Arc::new(InMemorySigner::generate())),
        }
    }

    /// From a 32-byte RFC 8032 seed. For tests and for keys you store
    /// yourself; prefer `from_keychain`.
    #[staticmethod]
    fn from_seed(seed: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| ArgumentError::new_err("seed must be exactly 32 bytes"))?;
        Ok(Self {
            inner: SharedSigner(Arc::new(InMemorySigner::from_seed(arr))),
        })
    }

    /// Load a key from the OS keychain; with `create=True`, create it if
    /// absent (never overwriting an existing one).
    #[staticmethod]
    #[pyo3(signature = (service, account, create = false))]
    fn from_keychain(service: &str, account: &str, create: bool) -> PyResult<Self> {
        use ogentic_audit_keychain::KeychainSigner;
        let k = if create {
            KeychainSigner::load_or_generate(service, account)
        } else {
            KeychainSigner::load(service, account)
        }
        .map_err(|e| IoFailure::new_err(e.to_string()))?;
        Ok(Self {
            inner: SharedSigner(Arc::new(k)),
        })
    }

    /// Create a new key in the OS keychain. Fails if one exists.
    #[staticmethod]
    fn create_in_keychain(service: &str, account: &str) -> PyResult<Self> {
        let k = ogentic_audit_keychain::KeychainSigner::create(service, account)
            .map_err(|e| ArgumentError::new_err(e.to_string()))?;
        Ok(Self {
            inner: SharedSigner(Arc::new(k)),
        })
    }

    /// `ssh-ed25519 AAAA… comment`.
    #[pyo3(signature = (comment = "ogentic-audit"))]
    fn public_key_openssh(&self, comment: &str) -> String {
        self.inner.public_key().to_openssh(comment)
    }

    /// PEM SubjectPublicKeyInfo.
    fn public_key_pem(&self) -> String {
        self.inner.public_key().to_pem()
    }

    /// 64 hex digits.
    fn public_key_hex(&self) -> String {
        self.inner.public_key().to_hex()
    }

    /// The fingerprint in 16 groups of 4 hex digits (the human form).
    fn fingerprint(&self) -> String {
        self.inner.public_key().fingerprint().to_grouped_hex()
    }

    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    fn fingerprint_openssh(&self) -> String {
        self.inner.public_key().fingerprint().to_openssh()
    }

    /// 64 lowercase hex digits, no separators.
    fn fingerprint_hex(&self) -> String {
        self.inner.public_key().fingerprint().to_hex()
    }

    fn __repr__(&self) -> String {
        format!("SigningKey({})", self.fingerprint())
    }
}

/// Convert a core JSON value into Python objects.
pub fn json_to_py(py: Python<'_>, v: &Value) -> PyResult<PyObject> {
    Ok(match v {
        Value::Null => py.None(),
        Value::Bool(b) => b.into_py_any(py)?,
        Value::Int(n) => n.into_py_any(py)?,
        Value::String(s) => s.into_py_any(py)?,
        Value::Array(items) => {
            let l = PyList::empty(py);
            for i in items {
                l.append(json_to_py(py, i)?)?;
            }
            l.into_py_any(py)?
        },
        Value::Object(m) => {
            let d = PyDict::new(py);
            for (k, val) in m {
                d.set_item(k, json_to_py(py, val)?)?;
            }
            d.into_py_any(py)?
        },
    })
}

fn arg<E: std::fmt::Display>(e: E) -> PyErr {
    ArgumentError::new_err(e.to_string())
}

/// Build a trust context from Python arguments (all argument errors).
pub fn trust_context(
    public_key: Option<&str>,
    key_fingerprint: Vec<String>,
    trust: Option<PathBuf>,
    statements: Vec<PathBuf>,
    revocations: Vec<PathBuf>,
) -> PyResult<TrustContext> {
    let mut t = TrustContext::new();
    if let Some(pk) = public_key {
        let p = Path::new(pk);
        let text = if p.is_file() {
            std::fs::read_to_string(p).map_err(arg)?
        } else {
            pk.to_string()
        };
        let key = PublicKey::parse(&text).map_err(arg)?;
        t.pin_key(key, None, Scope::DEFAULT).map_err(arg)?;
    }
    for f in &key_fingerprint {
        t.pin(f, None, Scope::DEFAULT).map_err(arg)?;
    }
    if let Some(path) = trust {
        let text = std::fs::read_to_string(&path).map_err(arg)?;
        t.add_allowed_signers(&text).map_err(arg)?;
    }
    for d in &statements {
        t.add_statements(d, true).map_err(arg)?;
    }
    for f in &revocations {
        t.add_revocation(f).map_err(arg)?;
    }
    Ok(t)
}

/// Report of a signed-log verification.
#[pyclass(
    name = "SignedVerifyReport",
    module = "ogentic_audit._native",
    unsendable
)]
pub struct PySignedReport {
    inner: s::SignedVerifyReport,
    /// `"Verified"`, `"SelfConsistent"` or `"Violation"`.
    #[pyo3(get)]
    pub verdict: String,
    /// `True` only for `"Verified"`.
    #[pyo3(get)]
    pub ok: bool,
    /// `"Verified"`, `"SelfConsistent"`, or `"<Kind>@<location>"`.
    #[pyo3(get)]
    pub compact: String,
    /// `"Verified"`, `"SelfConsistent"`, or the first violation's kind.
    #[pyo3(get)]
    pub verdict_kind: String,
}

#[pymethods]
impl PySignedReport {
    /// The report as a dict (spec v0.2 §14, `format_version` 2).
    fn as_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        json_to_py(py, &self.inner.to_json())
    }

    /// The report as pretty JSON text.
    fn to_json(&self) -> String {
        self.inner.to_json().to_pretty()
    }

    /// The human report the command line prints.
    #[pyo3(signature = (ascii = false, program = "python -m ogentic_audit"))]
    fn render(&self, ascii: bool, program: &str) -> String {
        self.inner.render_human(ascii, program)
    }

    /// Why the verdict is `SelfConsistent` (`not_pinned`,
    /// `no_signed_records`), else None.
    #[getter]
    fn reason(&self) -> Option<&'static str> {
        self.inner.not_verified_reason.map(|r| r.as_str())
    }

    #[getter]
    fn final_record_hash_hex(&self) -> Option<String> {
        self.inner.log.final_record_hash.map(|h| s::hex(&h))
    }

    #[getter]
    fn log_id_hex(&self) -> Option<String> {
        self.inner.log.log_id.map(|h| s::hex(&h))
    }

    #[getter]
    fn head_anchored(&self) -> bool {
        self.inner.log.head_anchored
    }

    #[getter]
    fn sealed(&self) -> bool {
        self.inner.log.sealed
    }

    #[getter]
    fn records_inspected(&self) -> u64 {
        self.inner.log.records_inspected
    }

    #[getter]
    fn segments_inspected(&self) -> u32 {
        self.inner.log.segments_inspected
    }

    /// Positions (`"s0r1"`) of records carried without their bodies.
    #[getter]
    fn elided_records(&self) -> Vec<String> {
        self.inner
            .log
            .elided_records
            .iter()
            .map(|(a, b)| format!("s{a}r{b}"))
            .collect()
    }

    #[getter]
    fn signer(&self, py: Python<'_>) -> PyResult<PyObject> {
        match &self.inner.signer {
            Some(sg) => json_to_py(py, &sg.to_json()),
            None => Ok(py.None()),
        }
    }

    #[getter]
    fn violation(&self, py: Python<'_>) -> PyResult<PyObject> {
        match self.inner.violation() {
            Some(v) => json_to_py(py, &v.to_json()),
            None => Ok(py.None()),
        }
    }

    #[getter]
    fn additional_violations(&self, py: Python<'_>) -> PyResult<PyObject> {
        let l = PyList::empty(py);
        for v in self.inner.violations.iter().skip(1) {
            l.append(json_to_py(py, &v.to_json())?)?;
        }
        l.into_py_any(py)
    }

    #[getter]
    fn warnings(&self, py: Python<'_>) -> PyResult<PyObject> {
        let d = json_to_py(py, &self.inner.to_json())?;
        Ok(d.bind(py).get_item("warnings")?.unbind())
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedVerifyReport(verdict={:?}, compact={:?}, records_inspected={})",
            self.verdict, self.compact, self.inner.log.records_inspected
        )
    }
}

fn verdict_str(v: Verdict) -> &'static str {
    s::report::verdict_str(v)
}

/// Format version of the log in `log_dir` (`None` when there are no
/// segment files; 0 when the first segment is unreadable).
#[pyfunction]
pub fn log_format(log_dir: &str) -> PyResult<Option<u16>> {
    s::log_format(log_dir).map_err(|e| IoFailure::new_err(e.to_string()))
}

/// Verify a signed log. See the Python `verify` wrapper.
#[pyfunction]
#[pyo3(signature = (log_dir, *, public_key = None, key_fingerprint = vec![], trust = None, statements = vec![], revocations = vec![], checkpoints = vec![], witnesses = vec![], expect_log_id = None, forensic = false, segment = None, raise_on_violation = false))]
pub fn verify_signed(
    log_dir: &str,
    public_key: Option<&str>,
    key_fingerprint: Vec<String>,
    trust: Option<PathBuf>,
    statements: Vec<PathBuf>,
    revocations: Vec<PathBuf>,
    checkpoints: Vec<PathBuf>,
    witnesses: Vec<PathBuf>,
    expect_log_id: Option<&str>,
    forensic: bool,
    segment: Option<u16>,
    raise_on_violation: bool,
) -> PyResult<PySignedReport> {
    let t = trust_context(public_key, key_fingerprint, trust, statements, revocations)?;
    let mut opts = SignedVerifyOptions::new().forensic(forensic || segment.is_some());
    let mut cps = Vec::new();
    for c in &checkpoints {
        cps.push(SuppliedCheckpoint::load(c).map_err(arg)?);
    }
    for w in &witnesses {
        let bytes = std::fs::read(w).map_err(arg)?;
        let parsed = s::WitnessCosignature::parse(&bytes).map_err(arg)?;
        let target = cps
            .iter_mut()
            .find(|c| s::sha256(&c.bytes) == parsed.checkpoint_sha256)
            .ok_or_else(|| ArgumentError::new_err("a witness co-signs none of the checkpoints"))?;
        target.add_witness(w).map_err(arg)?;
    }
    for c in cps {
        opts = opts.checkpoint(c);
    }
    if let Some(id) = expect_log_id {
        let parsed: [u8; 16] = s::unhex(id.trim())
            .ok_or_else(|| ArgumentError::new_err("expect_log_id must be 32 hex digits"))?;
        opts = opts.expect_log_id(parsed);
    }
    let mut report = SignedVerifier::new(t)
        .verify_with_options(log_dir, opts)
        .map_err(|e| match e.exit_code() {
            2 => IoFailure::new_err(e.to_string()),
            _ => ArgumentError::new_err(e.to_string()),
        })?;
    if let Some(n) = segment {
        report = report.filter_segment(n);
    }
    if raise_on_violation {
        match report.verdict {
            Verdict::Verified => {},
            Verdict::SelfConsistent => {
                return Err(SignerNotPinnedError::new_err(
                    report.render_human(true, "python -m ogentic_audit"),
                ))
            },
            _ => {
                let (kind, msg) = report
                    .violation()
                    .map(|v| (v.kind.as_str(), v.message.clone()))
                    .unwrap_or(("Violation", "verification failed".into()));
                return Err(signed_violation_exception(kind, &msg));
            },
        }
    }
    let verdict = verdict_str(report.verdict).to_string();
    let compact = report.compact_verdict();
    let verdict_kind = match report.verdict {
        Verdict::Verified | Verdict::SelfConsistent => verdict.clone(),
        _ => report
            .violation()
            .map_or("Violation".into(), |v| v.kind.as_str().to_string()),
    };
    Ok(PySignedReport {
        ok: report.verdict == Verdict::Verified,
        verdict,
        compact,
        verdict_kind,
        inner: report,
    })
}

/// Report of a release verification.
#[pyclass(name = "ReleaseReport", module = "ogentic_audit._native", unsendable)]
pub struct PyReleaseReport {
    inner: s::ReleaseReport,
    /// `"Verified"`, `"SelfConsistent"` or `"Violation"`.
    #[pyo3(get)]
    pub verdict: String,
    /// `True` only for `"Verified"`.
    #[pyo3(get)]
    pub ok: bool,
    /// `"Verified"`, `"SelfConsistent"`, or `"<Kind>@<item>"`.
    #[pyo3(get)]
    pub compact: String,
}

#[pymethods]
impl PyReleaseReport {
    /// The report as a dict (`ogentic-audit-release-report/v1`).
    fn as_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        json_to_py(py, &self.inner.to_json())
    }

    /// The report as pretty JSON text.
    fn to_json(&self) -> String {
        self.inner.to_json().to_pretty()
    }

    /// The human report the command line prints.
    #[pyo3(signature = (ascii = false, program = "python -m ogentic_audit"))]
    fn render(&self, ascii: bool, program: &str) -> String {
        self.inner.render_human(ascii, program)
    }

    /// `[{item, kind, reason, evidence, message}, …]`, every problem.
    #[getter]
    fn violations(&self, py: Python<'_>) -> PyResult<PyObject> {
        self._member(py, "violations")
    }

    #[getter]
    fn warnings(&self, py: Python<'_>) -> PyResult<PyObject> {
        self._member(py, "warnings")
    }

    /// `{attested, verified, unattested, ignored}`.
    #[getter]
    fn files(&self, py: Python<'_>) -> PyResult<PyObject> {
        self._member(py, "files")
    }

    #[getter]
    fn logs(&self, py: Python<'_>) -> PyResult<PyObject> {
        self._member(py, "logs")
    }

    #[getter]
    fn signer(&self, py: Python<'_>) -> PyResult<PyObject> {
        self._member(py, "signer")
    }

    #[getter]
    fn release_id(&self) -> Option<String> {
        self.inner.release_id.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ReleaseReport(verdict={:?}, compact={:?})",
            self.verdict, self.compact
        )
    }
}

impl PyReleaseReport {
    fn _member(&self, py: Python<'_>, key: &str) -> PyResult<PyObject> {
        let d = json_to_py(py, &self.inner.to_json())?;
        Ok(d.bind(py).get_item(key)?.unbind())
    }
}

/// Verify a release folder. See the Python `verify_release` wrapper.
#[pyfunction]
#[pyo3(signature = (release_dir, *, public_key = None, key_fingerprint = vec![], trust = None, statements = vec![], revocations = vec![], witnesses = vec![], expect_release_id = None, allow_unattested = false))]
pub fn verify_release(
    release_dir: &str,
    public_key: Option<&str>,
    key_fingerprint: Vec<String>,
    trust: Option<PathBuf>,
    statements: Vec<PathBuf>,
    revocations: Vec<PathBuf>,
    witnesses: Vec<PathBuf>,
    expect_release_id: Option<String>,
    allow_unattested: bool,
) -> PyResult<PyReleaseReport> {
    let t = trust_context(public_key, key_fingerprint, trust, statements, revocations)?;
    let mut opts = ReleaseOptions::new().allow_unattested(allow_unattested);
    if let Some(id) = expect_release_id {
        opts = opts.expect_release_id(id);
    }
    opts.witnesses = witnesses;
    let rep = s::verify_release(release_dir, &t, &opts).map_err(|e| match e {
        s::ReleaseError::Io(m) => IoFailure::new_err(m),
        other => ArgumentError::new_err(other.to_string()),
    })?;
    Ok(PyReleaseReport {
        ok: rep.verdict == Verdict::Verified,
        verdict: verdict_str(rep.verdict).to_string(),
        compact: rep.compact_verdict(),
        inner: rep,
    })
}

/// `(path, role, [(name, offset, length), …])`.
type FileArg = (String, Option<String>, Vec<(String, u64, u64)>);
/// `(source_dir, path_in_release, head, [(segment, record), …])`.
type LogArg = (PathBuf, String, Option<(u16, u64)>, Vec<(u16, u64)>);

/// Build and sign a release attestation. Returns its SHA-256 (hex), the
/// value `final_releases` and `trusted_releases` name.
///
/// `files`: list of `(path, role or None, [(name, offset, length), …])`.
/// `logs`: list of `(source_dir, path_in_release, head or None, [(segment, record), …])`.
#[pyfunction]
#[pyo3(signature = (release_dir, *, files, logs, signing_key, release_id, created_at = None))]
pub fn attest_release(
    release_dir: &str,
    files: Vec<FileArg>,
    logs: Vec<LogArg>,
    signing_key: &PySigningKey,
    release_id: &str,
    created_at: Option<String>,
) -> PyResult<String> {
    let mut b = AttestationBuilder::new(release_dir, release_id);
    for (path, role, parts) in files {
        let mut f = FileSpec::new(path).parts(
            parts
                .into_iter()
                .map(|(name, offset, length)| Part {
                    name,
                    offset,
                    length,
                })
                .collect(),
        );
        if let Some(r) = role {
            f = f.role(r);
        }
        b.add_file(f);
    }
    for (source, path, head, elide) in logs {
        b.add_log(LogSpec {
            source,
            path,
            head,
            elide,
        });
    }
    if let Some(c) = created_at {
        b.created_at(c);
    }
    let d = b.write(&signing_key.inner).map_err(|e| match e {
        s::ReleaseError::Io(m) => IoFailure::new_err(m),
        other => ArgumentError::new_err(other.to_string()),
    })?;
    Ok(d.to_hex())
}

/// A v2 checkpoint of a signed log (verified first), as canonical JSON
/// bytes, and its signature when `signing_key` (the log's own key) is
/// given.
#[pyfunction]
#[pyo3(signature = (log_dir, *, observed_at, signing_key = None))]
pub fn checkpoint_signed(
    py: Python<'_>,
    log_dir: &str,
    observed_at: &str,
    signing_key: Option<&PySigningKey>,
) -> PyResult<(PyObject, Option<String>)> {
    let report = SignedVerifier::new(TrustContext::new())
        .verify(log_dir)
        .map_err(arg)?;
    if report.verdict == Verdict::Violation {
        return Err(signed_violation_exception(
            report.violation().map_or("Violation", |v| v.kind.as_str()),
            &format!(
                "refusing to checkpoint a log that does not verify: {}",
                report.compact_verdict()
            ),
        ));
    }
    let l = &report.log;
    let (Some((segment, record_id)), Some(hash), Some(key_id), Some(log_id), Some(ts)) = (
        l.head,
        l.final_record_hash,
        l.key_id,
        l.log_id,
        l.head_ts_wall.clone(),
    ) else {
        return Err(ArgumentError::new_err(
            "log has no records — nothing to checkpoint",
        ));
    };
    if s::parse_rfc3339_millis(observed_at).is_none() {
        return Err(ArgumentError::new_err(
            "observed_at must be RFC 3339 UTC with milliseconds",
        ));
    }
    let cp = s::CheckpointV2 {
        alg: s::SigAlg::Ed25519,
        key_id,
        head: s::Head {
            log_id,
            segment,
            record_id,
            record_count: l.records_inspected,
            record_hash: hash,
        },
        head_ts_wall: ts,
        observed_at: Some(observed_at.to_string()),
    };
    let bytes = cp.to_bytes();
    let sig = match signing_key {
        Some(k) => {
            if k.inner.public_key().fingerprint() != key_id {
                return Err(ArgumentError::new_err(
                    "only the log's own key signs its checkpoints",
                ));
            }
            Some(s::CheckpointV2::sign(&bytes, &k.inner).map_err(arg)?)
        },
        None => None,
    };
    Ok((PyBytes::new(py, &bytes).into_py_any(py)?, sig))
}
