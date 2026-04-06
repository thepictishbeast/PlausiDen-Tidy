//! Age analyzer — identify files untouched for a configurable window.

use crate::scanner::FileEntry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single aged-file record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgedFile {
    pub path: PathBuf,
    pub size: u64,
    pub last_access: DateTime<Utc>,
    pub days_since_access: i64,
}

/// Report returned by [`AgeAnalyzer::analyze`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgeReport {
    pub threshold_days: i64,
    pub matched: usize,
    pub total_bytes: u64,
    pub files: Vec<AgedFile>,
}

/// Age analyzer.
pub struct AgeAnalyzer {
    threshold_days: i64,
    max_results: usize,
    now: DateTime<Utc>,
}

impl AgeAnalyzer {
    pub fn new(threshold_days: i64) -> Self {
        Self {
            threshold_days,
            max_results: usize::MAX,
            now: Utc::now(),
        }
    }

    pub fn with_max_results(mut self, n: usize) -> Self {
        self.max_results = n;
        self
    }

    pub fn with_now(mut self, now: DateTime<Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn analyze(&self, entries: &[FileEntry]) -> AgeReport {
        let mut matched: Vec<AgedFile> = entries
            .iter()
            .filter(|e| !e.is_dir)
            .filter_map(|e| {
                let reference = e.accessed.max(e.modified);
                let delta = self.now - reference;
                let days = delta.num_days();
                if days >= self.threshold_days {
                    Some(AgedFile {
                        path: e.path.clone(),
                        size: e.size,
                        last_access: reference,
                        days_since_access: days,
                    })
                } else {
                    None
                }
            })
            .collect();

        matched.sort_by(|a, b| b.days_since_access.cmp(&a.days_since_access));
        matched.truncate(self.max_results);

        let total_bytes: u64 = matched.iter().map(|a| a.size).sum();
        AgeReport {
            threshold_days: self.threshold_days,
            matched: matched.len(),
            total_bytes,
            files: matched,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn entry(path: &str, size: u64, age_days: i64, now: DateTime<Utc>) -> FileEntry {
        let accessed = now - Duration::days(age_days);
        FileEntry {
            path: PathBuf::from(path),
            size,
            modified: accessed,
            accessed,
            is_symlink: false,
            is_dir: false,
        }
    }

    #[test]
    fn test_flags_old_files() {
        let now = Utc::now();
        let entries = vec![
            entry("/a", 100, 400, now),
            entry("/b", 100, 10, now),
        ];
        let r = AgeAnalyzer::new(365).with_now(now).analyze(&entries);
        assert_eq!(r.matched, 1);
        assert_eq!(r.files[0].path, PathBuf::from("/a"));
    }

    #[test]
    fn test_threshold_boundary() {
        let now = Utc::now();
        let entries = vec![entry("/a", 100, 365, now)];
        let r = AgeAnalyzer::new(365).with_now(now).analyze(&entries);
        assert_eq!(r.matched, 1);
    }

    #[test]
    fn test_sorted_descending_age() {
        let now = Utc::now();
        let entries = vec![
            entry("/young", 100, 400, now),
            entry("/oldest", 100, 1000, now),
            entry("/middle", 100, 700, now),
        ];
        let r = AgeAnalyzer::new(365).with_now(now).analyze(&entries);
        assert_eq!(r.files[0].path, PathBuf::from("/oldest"));
        assert_eq!(r.files[2].path, PathBuf::from("/young"));
    }

    #[test]
    fn test_total_bytes_summed() {
        let now = Utc::now();
        let entries = vec![
            entry("/a", 100, 400, now),
            entry("/b", 250, 500, now),
        ];
        let r = AgeAnalyzer::new(365).with_now(now).analyze(&entries);
        assert_eq!(r.total_bytes, 350);
    }

    #[test]
    fn test_max_results_truncates() {
        let now = Utc::now();
        let entries: Vec<FileEntry> = (0..10)
            .map(|i| entry(&format!("/f{}", i), 100, 400 + i, now))
            .collect();
        let r = AgeAnalyzer::new(100)
            .with_max_results(3)
            .with_now(now)
            .analyze(&entries);
        assert_eq!(r.matched, 3);
    }

    #[test]
    fn test_empty_entries() {
        let r = AgeAnalyzer::new(30).analyze(&[]);
        assert_eq!(r.matched, 0);
    }

    #[test]
    fn test_skips_directories() {
        let now = Utc::now();
        let mut e = entry("/dir", 0, 500, now);
        e.is_dir = true;
        let r = AgeAnalyzer::new(30).with_now(now).analyze(&[e]);
        assert_eq!(r.matched, 0);
    }

    #[test]
    fn test_uses_more_recent_of_mtime_and_atime() {
        let now = Utc::now();
        let recent = now - Duration::days(1);
        let ancient = now - Duration::days(1000);
        let e = FileEntry {
            path: PathBuf::from("/x"),
            size: 1,
            modified: ancient,
            accessed: recent,
            is_symlink: false,
            is_dir: false,
        };
        let r = AgeAnalyzer::new(30).with_now(now).analyze(&[e]);
        assert_eq!(r.matched, 0);
    }

    #[test]
    fn test_threshold_below_zero_allows_all() {
        let now = Utc::now();
        let e = entry("/x", 1, 0, now);
        let r = AgeAnalyzer::new(0).with_now(now).analyze(&[e]);
        assert_eq!(r.matched, 1);
    }

    #[test]
    fn test_report_records_threshold() {
        let r = AgeAnalyzer::new(123).analyze(&[]);
        assert_eq!(r.threshold_days, 123);
    }
}
