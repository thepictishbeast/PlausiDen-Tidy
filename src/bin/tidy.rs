//! `tidy` — command-line entry point.
//!
//! The CLI is a convenience wrapper; the primary UX target is the
//! egui frontend that lives alongside this binary in a later commit.

use plausiden_tidy::age_analyzer::AgeAnalyzer;
use plausiden_tidy::dedup::Deduplicator;
use plausiden_tidy::importance::ImportanceClassifier;
use plausiden_tidy::scanner::{ScanOptions, Scanner};
use plausiden_tidy::size_analyzer::SizeAnalyzer;
use std::env;
use std::process::ExitCode;

const USAGE: &str = "\
plausiden-tidy 0.1 — smart filesystem cleaner (dry-run only)

USAGE:
    tidy scan <path>
    tidy duplicates <path>
    tidy old --days <N> <path>
    tidy large --top <N> <path>

All commands are read-only. They produce reports on stdout and never
delete anything. The egui frontend is the primary interface — launch
it with `tidy-gui` (in a separate crate).
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{}", USAGE);
        return ExitCode::from(2);
    }

    match args[0].as_str() {
        "scan" => {
            let Some(path) = args.get(1) else {
                eprintln!("scan requires <path>");
                return ExitCode::from(2);
            };
            let mut s = Scanner::new(ScanOptions::default());
            if let Err(e) = s.scan(path) {
                eprintln!("scan error: {}", e);
                return ExitCode::from(1);
            }
            let r = s.report();
            println!("Scanned {} files, {} directories, {} bytes",
                r.files_scanned, r.dirs_scanned, r.total_bytes);
            println!("Hidden skipped: {}  Symlinks skipped: {}  I/O errors: {}",
                r.skipped_hidden, r.skipped_symlink, r.io_errors);
            ExitCode::SUCCESS
        }
        "duplicates" => {
            let Some(path) = args.get(1) else {
                eprintln!("duplicates requires <path>");
                return ExitCode::from(2);
            };
            let mut s = Scanner::new(ScanOptions::default());
            if let Err(e) = s.scan(path) {
                eprintln!("scan error: {}", e);
                return ExitCode::from(1);
            }
            let report = Deduplicator::new().find(s.entries());
            println!("Duplicate groups: {}", report.groups_found);
            println!("Files in groups: {}", report.files_in_groups);
            println!("Reclaimable bytes: {}", report.total_wasted_bytes);
            for (i, group) in report.groups.iter().enumerate().take(20) {
                println!("\n[{}] digest {}... size {} bytes",
                    i + 1, &group.digest[..16], group.size);
                for p in &group.paths {
                    println!("    {}", p.display());
                }
            }
            ExitCode::SUCCESS
        }
        "old" => {
            let mut days: i64 = 365;
            let mut path: Option<&String> = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--days" {
                    if let Some(v) = args.get(i + 1).and_then(|v| v.parse().ok()) {
                        days = v;
                        i += 2;
                        continue;
                    }
                }
                path = Some(&args[i]);
                i += 1;
            }
            let Some(path) = path else {
                eprintln!("old requires <path>");
                return ExitCode::from(2);
            };
            let mut s = Scanner::new(ScanOptions::default());
            if let Err(e) = s.scan(path) {
                eprintln!("scan error: {}", e);
                return ExitCode::from(1);
            }
            let r = AgeAnalyzer::new(days).analyze(s.entries());
            let classifier = ImportanceClassifier::new();
            println!("Found {} files older than {} days ({} bytes)",
                r.matched, r.threshold_days, r.total_bytes);
            for f in r.files.iter().take(40) {
                let verdict = classifier.classify(&f.path);
                println!("  {:>6} days  {:>10} B  [{:?}]  {}",
                    f.days_since_access, f.size, verdict.importance, f.path.display());
            }
            ExitCode::SUCCESS
        }
        "large" => {
            let mut top: usize = 50;
            let mut path: Option<&String> = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--top" {
                    if let Some(v) = args.get(i + 1).and_then(|v| v.parse().ok()) {
                        top = v;
                        i += 2;
                        continue;
                    }
                }
                path = Some(&args[i]);
                i += 1;
            }
            let Some(path) = path else {
                eprintln!("large requires <path>");
                return ExitCode::from(2);
            };
            let mut s = Scanner::new(ScanOptions::default());
            if let Err(e) = s.scan(path) {
                eprintln!("scan error: {}", e);
                return ExitCode::from(1);
            }
            let r = SizeAnalyzer::new(top).analyze(s.entries());
            let classifier = ImportanceClassifier::new();
            println!("Top {} files by size ({:.1}% of scanned bytes)",
                r.files.len(), r.top_share() * 100.0);
            for f in &r.files {
                let verdict = classifier.classify(&f.path);
                println!("  {:>14} B  [{:?}]  {}",
                    f.size, verdict.importance, f.path.display());
            }
            ExitCode::SUCCESS
        }
        "--help" | "-h" | "help" => {
            println!("{}", USAGE);
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command: {}", other);
            eprintln!("{}", USAGE);
            ExitCode::from(2)
        }
    }
}
