//! Size analyzer — rank the largest files in a scan.

use crate::scanner::FileEntry;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single large-file record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeFile {
    pub path: PathBuf,
    pub size: u64,
}

/// Report returned by [`SizeAnalyzer::analyze`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SizeReport {
    pub top_n: usize,
    pub files: Vec<LargeFile>,
    pub total_bytes_in_top: u64,
    pub total_bytes_in_scan: u64,
}

impl SizeReport {
    pub fn top_share(&self) -> f64 {
        if self.total_bytes_in_scan == 0 {
            0.0
        } else {
            self.total_bytes_in_top as f64 / self.total_bytes_in_scan as f64
        }
    }
}

/// Size analyzer.
pub struct SizeAnalyzer {
    top_n: usize,
    min_size: u64,
}

impl SizeAnalyzer {
    pub fn new(top_n: usize) -> Self {
        Self {
            top_n,
            min_size: 1,
        }
    }

    pub fn with_min_size(mut self, min_size: u64) -> Self {
        self.min_size = min_size;
        self
    }

    pub fn analyze(&self, entries: &[FileEntry]) -> SizeReport {
        let mut scan_total: u64 = 0;
        let mut candidates: Vec<LargeFile> = entries
            .iter()
            .filter(|e| !e.is_dir)
            .filter(|e| e.size >= self.min_size)
            .inspect(|e| scan_total += e.size)
            .map(|e| LargeFile {
                path: e.path.clone(),
                size: e.size,
            })
            .collect();

        candidates.sort_by(|a, b| b.size.cmp(&a.size));
        candidates.truncate(self.top_n);
        let total_bytes_in_top = candidates.iter().map(|f| f.size).sum();

        SizeReport {
            top_n: self.top_n,
            files: candidates,
            total_bytes_in_top,
            total_bytes_in_scan: scan_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn entry(path: &str, size: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size,
            modified: Utc::now(),
            accessed: Utc::now(),
            is_symlink: false,
            is_dir: false,
        }
    }

    #[test]
    fn test_ranks_by_size_desc() {
        let entries = vec![
            entry("/small", 100),
            entry("/huge", 10_000),
            entry("/medium", 1_000),
        ];
        let r = SizeAnalyzer::new(10).analyze(&entries);
        assert_eq!(r.files[0].path, PathBuf::from("/huge"));
        assert_eq!(r.files[1].path, PathBuf::from("/medium"));
        assert_eq!(r.files[2].path, PathBuf::from("/small"));
    }

    #[test]
    fn test_top_n_truncation() {
        let entries: Vec<FileEntry> = (0..20)
            .map(|i| entry(&format!("/f{}", i), 1000 + i as u64))
            .collect();
        let r = SizeAnalyzer::new(5).analyze(&entries);
        assert_eq!(r.files.len(), 5);
    }

    #[test]
    fn test_total_bytes_in_scan() {
        let entries = vec![entry("/a", 100), entry("/b", 200)];
        let r = SizeAnalyzer::new(10).analyze(&entries);
        assert_eq!(r.total_bytes_in_scan, 300);
    }

    #[test]
    fn test_top_share_computation() {
        let entries = vec![entry("/big", 900), entry("/rest", 100)];
        let r = SizeAnalyzer::new(1).analyze(&entries);
        assert!((r.top_share() - 0.9).abs() < 1e-9);
    }

    #[test]
    fn test_top_share_empty_scan_is_zero() {
        let r = SizeReport::default();
        assert_eq!(r.top_share(), 0.0);
    }

    #[test]
    fn test_min_size_filter() {
        let entries = vec![entry("/small", 10), entry("/big", 1000)];
        let r = SizeAnalyzer::new(10).with_min_size(500).analyze(&entries);
        assert_eq!(r.files.len(), 1);
    }

    #[test]
    fn test_skips_directories() {
        let mut dir = entry("/d", 0);
        dir.is_dir = true;
        let r = SizeAnalyzer::new(10).analyze(&[dir]);
        assert_eq!(r.files.len(), 0);
    }

    #[test]
    fn test_total_bytes_in_top_sum() {
        let entries = vec![entry("/a", 100), entry("/b", 200), entry("/c", 300)];
        let r = SizeAnalyzer::new(2).analyze(&entries);
        assert_eq!(r.total_bytes_in_top, 500);
    }

    #[test]
    fn test_empty_report() {
        let r = SizeAnalyzer::new(10).analyze(&[]);
        assert_eq!(r.files.len(), 0);
        assert_eq!(r.total_bytes_in_scan, 0);
    }

    #[test]
    fn test_top_n_larger_than_entries() {
        let entries = vec![entry("/a", 100)];
        let r = SizeAnalyzer::new(100).analyze(&entries);
        assert_eq!(r.files.len(), 1);
    }
}
