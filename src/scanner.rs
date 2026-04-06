//! Metadata-only filesystem scanner.
//!
//! The scanner walks a directory tree collecting [`FileEntry`] records that
//! carry path, size, mtime, atime, and inode — nothing more. It does not
//! read file contents. Content-reading operations (BLAKE3 hashing for
//! duplicate detection) live in the `dedup` module and are opt-in.

use crate::error::{Result, TidyError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

/// One file as observed by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub is_symlink: bool,
    pub is_dir: bool,
}

impl FileEntry {
    pub fn age_days(&self, now: DateTime<Utc>) -> i64 {
        (now - self.accessed.max(self.modified))
            .num_days()
            .max(0)
    }

    pub fn from_metadata(path: PathBuf, meta: &Metadata) -> Self {
        let modified = system_time_to_utc(meta.modified().ok());
        let accessed = system_time_to_utc(meta.accessed().ok());
        Self {
            path,
            size: meta.len(),
            modified,
            accessed,
            is_symlink: meta.file_type().is_symlink(),
            is_dir: meta.is_dir(),
        }
    }
}

fn system_time_to_utc(t: Option<SystemTime>) -> DateTime<Utc> {
    match t {
        Some(t) => DateTime::<Utc>::from(t),
        None => DateTime::<Utc>::from(SystemTime::UNIX_EPOCH),
    }
}

/// Options controlling a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub follow_symlinks: bool,
    pub max_depth: Option<usize>,
    pub min_size: u64,
    pub include_hidden: bool,
    pub skip_mounts: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            follow_symlinks: false,
            max_depth: None,
            min_size: 0,
            include_hidden: false,
            skip_mounts: true,
        }
    }
}

/// Summary emitted after a scan completes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanReport {
    pub files_scanned: u64,
    pub dirs_scanned: u64,
    pub total_bytes: u64,
    pub skipped_hidden: u64,
    pub skipped_symlink: u64,
    pub io_errors: u64,
    pub roots: Vec<PathBuf>,
}

/// Metadata-only filesystem scanner.
pub struct Scanner {
    options: ScanOptions,
    report: ScanReport,
    entries: Vec<FileEntry>,
}

impl Scanner {
    pub fn new(options: ScanOptions) -> Self {
        Self {
            options,
            report: ScanReport::default(),
            entries: Vec::new(),
        }
    }

    /// Walk `root` and collect entries. The scanner never reads file
    /// contents; every byte it records comes from `stat`-equivalent calls.
    pub fn scan(&mut self, root: impl AsRef<Path>) -> Result<()> {
        let root = root.as_ref();
        if !root.exists() {
            return Err(TidyError::NotFound(root.to_path_buf()));
        }
        self.report.roots.push(root.to_path_buf());

        let mut walker = WalkDir::new(root).follow_links(self.options.follow_symlinks);
        if let Some(d) = self.options.max_depth {
            walker = walker.max_depth(d);
        }
        if self.options.skip_mounts {
            walker = walker.same_file_system(true);
        }

        for dent in walker {
            let dent = match dent {
                Ok(d) => d,
                Err(_) => {
                    self.report.io_errors += 1;
                    continue;
                }
            };

            let file_name = dent
                .path()
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if !self.options.include_hidden && file_name.starts_with('.') && dent.depth() > 0 {
                self.report.skipped_hidden += 1;
                continue;
            }

            let meta = match dent.metadata() {
                Ok(m) => m,
                Err(_) => {
                    self.report.io_errors += 1;
                    continue;
                }
            };

            if meta.file_type().is_symlink() && !self.options.follow_symlinks {
                self.report.skipped_symlink += 1;
                continue;
            }

            if meta.is_dir() {
                self.report.dirs_scanned += 1;
                continue;
            }

            if meta.len() < self.options.min_size {
                continue;
            }

            self.report.files_scanned += 1;
            self.report.total_bytes += meta.len();
            self.entries.push(FileEntry::from_metadata(
                dent.path().to_path_buf(),
                &meta,
            ));
        }

        Ok(())
    }

    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    pub fn report(&self) -> &ScanReport {
        &self.report
    }

    pub fn into_entries(self) -> Vec<FileEntry> {
        self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn make_temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tidy-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    #[test]
    fn test_scan_finds_files() {
        let dir = make_temp_dir();
        write_file(&dir, "a.txt", b"hello");
        write_file(&dir, "b.txt", b"world");
        let mut s = Scanner::new(ScanOptions::default());
        s.scan(&dir).unwrap();
        assert_eq!(s.entries().len(), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_scan_reports_totals() {
        let dir = make_temp_dir();
        write_file(&dir, "a", &[0u8; 100]);
        write_file(&dir, "b", &[0u8; 200]);
        let mut s = Scanner::new(ScanOptions::default());
        s.scan(&dir).unwrap();
        assert_eq!(s.report().files_scanned, 2);
        assert_eq!(s.report().total_bytes, 300);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_scan_skips_hidden_by_default() {
        let dir = make_temp_dir();
        write_file(&dir, ".hidden", b"x");
        write_file(&dir, "visible", b"x");
        let mut s = Scanner::new(ScanOptions::default());
        s.scan(&dir).unwrap();
        assert_eq!(s.entries().len(), 1);
        assert_eq!(s.report().skipped_hidden, 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_scan_min_size_filter() {
        let dir = make_temp_dir();
        write_file(&dir, "small", b"1");
        write_file(&dir, "big", &[0u8; 1000]);
        let opts = ScanOptions {
            min_size: 500,
            ..Default::default()
        };
        let mut s = Scanner::new(opts);
        s.scan(&dir).unwrap();
        assert_eq!(s.entries().len(), 1);
        assert_eq!(s.entries()[0].size, 1000);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_scan_nonexistent_root_errors() {
        let mut s = Scanner::new(ScanOptions::default());
        let err = s.scan("/tmp/this-path-should-definitely-not-exist-xzq-123").unwrap_err();
        assert!(matches!(err, TidyError::NotFound(_)));
    }

    #[test]
    fn test_scan_respects_max_depth() {
        let dir = make_temp_dir();
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        write_file(&dir, "top", b"x");
        write_file(&sub, "nested", b"x");
        let opts = ScanOptions {
            max_depth: Some(1),
            ..Default::default()
        };
        let mut s = Scanner::new(opts);
        s.scan(&dir).unwrap();
        assert_eq!(s.entries().len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_file_entry_age_days_nonnegative() {
        let e = FileEntry {
            path: PathBuf::from("/tmp/x"),
            size: 0,
            modified: Utc::now(),
            accessed: Utc::now(),
            is_symlink: false,
            is_dir: false,
        };
        assert!(e.age_days(Utc::now()) >= 0);
    }

    #[test]
    fn test_scan_records_root() {
        let dir = make_temp_dir();
        let mut s = Scanner::new(ScanOptions::default());
        s.scan(&dir).unwrap();
        assert_eq!(s.report().roots.len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_include_hidden_when_enabled() {
        let dir = make_temp_dir();
        write_file(&dir, ".dotfile", b"x");
        let opts = ScanOptions {
            include_hidden: true,
            ..Default::default()
        };
        let mut s = Scanner::new(opts);
        s.scan(&dir).unwrap();
        assert_eq!(s.entries().len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_into_entries_consumes_scanner() {
        let dir = make_temp_dir();
        write_file(&dir, "a", b"x");
        let mut s = Scanner::new(ScanOptions::default());
        s.scan(&dir).unwrap();
        let entries = s.into_entries();
        assert_eq!(entries.len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_scan_report_default_is_zero() {
        let r = ScanReport::default();
        assert_eq!(r.files_scanned, 0);
        assert_eq!(r.total_bytes, 0);
    }
}
