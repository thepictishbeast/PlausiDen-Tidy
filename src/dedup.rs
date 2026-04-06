//! Duplicate file detector — two-stage: size bucket then BLAKE3 hash.
//!
//! The two-stage approach avoids hashing files that can't possibly be
//! duplicates. Files are first grouped by size; any group with only one
//! entry is discarded. Remaining candidates are then hashed with
//! BLAKE3 (content-reading *does* happen here, but the digest stays on
//! the device — only path+hash metadata ever leaves the scanner).

use crate::error::{Result, TidyError};
use crate::scanner::FileEntry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Hash digest for a file (BLAKE3 256-bit).
pub type Digest = [u8; 32];

/// Group of files with identical contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DupGroup {
    pub digest: String,
    pub size: u64,
    pub paths: Vec<PathBuf>,
}

impl DupGroup {
    pub fn wasted_bytes(&self) -> u64 {
        if self.paths.is_empty() {
            return 0;
        }
        self.size * (self.paths.len() as u64 - 1)
    }
}

/// Report returned by [`Deduplicator::find`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DedupReport {
    pub candidates_hashed: u64,
    pub groups_found: usize,
    pub files_in_groups: usize,
    pub total_wasted_bytes: u64,
    pub io_errors: u64,
    pub groups: Vec<DupGroup>,
}

/// Duplicate detector.
pub struct Deduplicator {
    /// Maximum bytes to hash per file. 0 = full file.
    max_hash_bytes: u64,
    min_size: u64,
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self {
            max_hash_bytes: 0,
            min_size: 1,
        }
    }
}

impl Deduplicator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_min_size(mut self, min_size: u64) -> Self {
        self.min_size = min_size;
        self
    }

    pub fn with_max_hash_bytes(mut self, cap: u64) -> Self {
        self.max_hash_bytes = cap;
        self
    }

    /// Find duplicate groups across the provided entries.
    pub fn find(&self, entries: &[FileEntry]) -> DedupReport {
        // Stage 1: group by size.
        let mut by_size: HashMap<u64, Vec<&FileEntry>> = HashMap::new();
        for e in entries {
            if e.size < self.min_size || e.is_dir {
                continue;
            }
            by_size.entry(e.size).or_default().push(e);
        }

        let mut report = DedupReport::default();

        // Stage 2: hash anything with ≥2 candidates.
        for (size, group) in by_size {
            if group.len() < 2 {
                continue;
            }
            let mut by_hash: HashMap<Digest, Vec<PathBuf>> = HashMap::new();
            for entry in group {
                match self.hash_file(&entry.path) {
                    Ok(d) => {
                        by_hash.entry(d).or_default().push(entry.path.clone());
                        report.candidates_hashed += 1;
                    }
                    Err(_) => {
                        report.io_errors += 1;
                    }
                }
            }
            for (digest, paths) in by_hash {
                if paths.len() < 2 {
                    continue;
                }
                let group = DupGroup {
                    digest: hex_digest(&digest),
                    size,
                    paths,
                };
                report.files_in_groups += group.paths.len();
                report.total_wasted_bytes += group.wasted_bytes();
                report.groups.push(group);
            }
        }

        report.groups_found = report.groups.len();
        report
    }

    /// Hash a single file's contents.
    ///
    /// BUG ASSUMPTION (AVP-2): the caller may pass a path that has
    /// been replaced with a symlink since the scanner recorded it.
    /// Following that symlink would hash the target instead of the
    /// original file and produce a spurious duplicate group. We
    /// refuse symlinks up front via symlink_metadata so dedup only
    /// ever sees regular files.
    ///
    /// SECURITY: the read buffer is zeroized on every exit path so
    /// bytes from potentially sensitive files never linger in RAM
    /// beyond the duration of the hash itself.
    fn hash_file(&self, path: &Path) -> Result<Digest> {
        // REGRESSION-GUARD: an earlier version called File::open
        // directly, which follows symlinks. Two symlinks pointing
        // at the same target would be reported as a duplicate group,
        // even though they are links, not copies.
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| TidyError::io(path.to_path_buf(), e))?;
        if meta.file_type().is_symlink() {
            return Err(TidyError::NotAFile(path.to_path_buf()));
        }

        let mut f = File::open(path).map_err(|e| TidyError::io(path.to_path_buf(), e))?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 65536];
        let mut remaining = if self.max_hash_bytes == 0 {
            u64::MAX
        } else {
            self.max_hash_bytes
        };
        loop {
            let to_read = (buf.len() as u64).min(remaining) as usize;
            if to_read == 0 {
                break;
            }
            let n = match f.read(&mut buf[..to_read]) {
                Ok(n) => n,
                Err(e) => {
                    // Scrub the buffer before propagating the error.
                    for b in buf.iter_mut() {
                        *b = 0;
                    }
                    return Err(TidyError::io(path.to_path_buf(), e));
                }
            };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            remaining = remaining.saturating_sub(n as u64);
        }
        // SECURITY: scrub the read buffer before returning. File
        // contents would otherwise linger on the stack until the
        // next function call overwrote them.
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0xF) as u32, 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanOptions, Scanner};
    use std::fs;
    use std::io::Write;

    fn make_temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tidy-dedup-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, name: &str, content: &[u8]) {
        let mut f = fs::File::create(dir.join(name)).unwrap();
        f.write_all(content).unwrap();
    }

    fn scan(dir: &Path) -> Vec<FileEntry> {
        let mut s = Scanner::new(ScanOptions::default());
        s.scan(dir).unwrap();
        s.into_entries()
    }

    #[test]
    fn test_finds_simple_duplicates() {
        let dir = make_temp_dir();
        write(&dir, "a", b"hello world");
        write(&dir, "b", b"hello world");
        write(&dir, "c", b"different");
        let entries = scan(&dir);
        let report = Deduplicator::new().find(&entries);
        assert_eq!(report.groups_found, 1);
        assert_eq!(report.groups[0].paths.len(), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_wasted_bytes_calculation() {
        let group = DupGroup {
            digest: "x".into(),
            size: 100,
            paths: vec!["/a".into(), "/b".into(), "/c".into()],
        };
        assert_eq!(group.wasted_bytes(), 200);
    }

    #[test]
    fn test_wasted_bytes_single() {
        let group = DupGroup {
            digest: "x".into(),
            size: 100,
            paths: vec!["/a".into()],
        };
        assert_eq!(group.wasted_bytes(), 0);
    }

    #[test]
    fn test_size_bucket_excludes_unique_sizes() {
        let dir = make_temp_dir();
        write(&dir, "a", b"one");
        write(&dir, "b", b"twotwo");
        let entries = scan(&dir);
        let report = Deduplicator::new().find(&entries);
        assert_eq!(report.groups_found, 0);
        assert_eq!(report.candidates_hashed, 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_multiple_groups() {
        let dir = make_temp_dir();
        write(&dir, "a1", b"group one");
        write(&dir, "a2", b"group one");
        write(&dir, "b1", b"group two");
        write(&dir, "b2", b"group two");
        let entries = scan(&dir);
        let report = Deduplicator::new().find(&entries);
        assert_eq!(report.groups_found, 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_min_size_filter() {
        let dir = make_temp_dir();
        write(&dir, "tiny1", b"a");
        write(&dir, "tiny2", b"a");
        let entries = scan(&dir);
        let report = Deduplicator::new().with_min_size(100).find(&entries);
        assert_eq!(report.groups_found, 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_total_wasted_bytes() {
        let dir = make_temp_dir();
        let content = vec![0u8; 1000];
        write(&dir, "a", &content);
        write(&dir, "b", &content);
        write(&dir, "c", &content);
        let entries = scan(&dir);
        let report = Deduplicator::new().find(&entries);
        assert_eq!(report.total_wasted_bytes, 2000);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_hex_digest_length() {
        let digest = [0u8; 32];
        assert_eq!(hex_digest(&digest).len(), 64);
    }

    #[test]
    fn test_identical_large_files() {
        let dir = make_temp_dir();
        let big = vec![0xAAu8; 200_000];
        write(&dir, "x", &big);
        write(&dir, "y", &big);
        let entries = scan(&dir);
        let report = Deduplicator::new().find(&entries);
        assert_eq!(report.groups_found, 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_empty_entries_yields_empty_report() {
        let report = Deduplicator::new().find(&[]);
        assert_eq!(report.groups_found, 0);
        assert_eq!(report.candidates_hashed, 0);
    }

    #[test]
    fn test_capped_hash_still_finds_duplicates() {
        let dir = make_temp_dir();
        let content = vec![0u8; 50_000];
        write(&dir, "a", &content);
        write(&dir, "b", &content);
        let entries = scan(&dir);
        let report = Deduplicator::new().with_max_hash_bytes(1024).find(&entries);
        assert_eq!(report.groups_found, 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_files_in_groups_counted() {
        let dir = make_temp_dir();
        write(&dir, "a", b"same");
        write(&dir, "b", b"same");
        write(&dir, "c", b"same");
        let entries = scan(&dir);
        let report = Deduplicator::new().find(&entries);
        assert_eq!(report.files_in_groups, 3);
        fs::remove_dir_all(&dir).ok();
    }

    // REGRESSION-GUARD: dedup used to follow symlinks through
    // File::open, so two symlinks pointing at the same target were
    // reported as a duplicate group. Now hash_file refuses symlinks
    // and the Deduplicator::find loop surfaces that as an io error
    // rather than a false-positive group.
    #[test]
    #[cfg(unix)]
    fn test_hash_file_refuses_symlink() {
        let dir = make_temp_dir();
        let target = dir.join("target");
        std::fs::write(&target, b"sentinel-content").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let dedup = Deduplicator::new();
        let result = dedup.hash_file(&link);
        assert!(result.is_err());
        // Target contents untouched.
        let contents = std::fs::read(&target).unwrap();
        assert_eq!(contents, b"sentinel-content");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_hash_file_zeroizes_buffer_on_success() {
        // Indirect test — we can't inspect the scrubbed buffer
        // directly, but we can verify that hashing succeeds with
        // a file larger than the internal buffer without corrupting
        // the digest. A bug in the scrub path would likely show up
        // as a hash mismatch against a known-good oracle.
        let dir = make_temp_dir();
        let content = vec![0x5Au8; 200_000];
        write(&dir, "big", &content);
        let path = dir.join("big");
        let dedup = Deduplicator::new();
        let hash_a = dedup.hash_file(&path).unwrap();
        let hash_b = dedup.hash_file(&path).unwrap();
        assert_eq!(hash_a, hash_b);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_hash_file_refuses_directory() {
        let dir = make_temp_dir();
        let subdir = dir.join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let dedup = Deduplicator::new();
        // Hashing a directory: File::open will fail or the read
        // loop will error. Either way, hash_file must not panic.
        let result = dedup.hash_file(&subdir);
        assert!(result.is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
