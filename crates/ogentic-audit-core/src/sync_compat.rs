//! Platform-aware fsync wrapper.
//!
//! On macOS, `fsync(2)` flushes data to the device driver but does **not**
//! force it onto the physical platter — the disk controller may still
//! hold the bytes in cache, and a power-loss event can lose data that
//! `fsync` already confirmed. The Apple-documented escape hatch is
//! `fcntl(F_FULLFSYNC)`, which forces the controller-side flush.
//!
//! `ogentic-audit` is a court-defensibility tool: if a record returns
//! successfully from `Writer::flush()` it MUST be durable, including
//! across a sudden power loss. This module exposes a single
//! [`full_sync`] function that picks the right primitive per platform:
//!
//! - macOS: `fcntl(F_FULLFSYNC)` via `rustix::fs::fcntl_fullfsync`
//!   (platform-gated; only compiled in when `cfg(target_os = "macos")`).
//! - everything else: [`File::sync_all`], which is the strongest
//!   primitive Rust's std exposes on the platform.
//!
//! Acceptance for [OGE-429 R1] specifies *"`fsync` (or `F_FULLFSYNC` on
//! macOS) on data + dir entry"* — this module handles the data side.
//! The directory-sync side is in [`crate::writer`].
//!
//! [OGE-429 R1]: https://linear.app/ogenticai/issue/OGE-429

use std::fs::File;
use std::io;

/// Force the OS to flush `file`'s data to durable storage. On macOS,
/// this uses `F_FULLFSYNC` (platter-level guarantee); on other
/// platforms it uses the strongest primitive Rust's std exposes.
pub fn full_sync(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd;
        rustix::fs::fcntl_fullfsync(file.as_fd()).map_err(io::Error::from)
    }
    #[cfg(not(target_os = "macos"))]
    {
        file.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn full_sync_on_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        let file = File::create(&path).unwrap();
        full_sync(&file).unwrap();
    }

    #[test]
    fn full_sync_after_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("written.bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"hello").unwrap();
        full_sync(&file).unwrap();
    }
}
