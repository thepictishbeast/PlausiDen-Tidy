//! # PlausiDen-Tidy
//!
//! Library crate for smart filesystem tidying — finds what can be
//! cleaned, classifies what must be protected, and hands back a
//! reviewable plan. The library itself never deletes: execution
//! always flows through a caller-supplied executor, and the default
//! [`action::FsExecutor`] is dry-run-only.
//!
//! The graphical frontend lives in the separate
//! [PlausiDen-Atrium](https://github.com/redcaptian1917/PlausiDen-Atrium)
//! crate. Antiforensic destruction lives in
//! [PlausiDen-Purge](https://github.com/redcaptian1917/PlausiDen-Purge).
//! Tidy focuses on *tidying* — the everyday cleanup loop.
//!
//! ## Design principles
//!
//! - **Metadata-first**. The scanner reads `stat` metadata, not file
//!   contents. Content reads happen only where strictly necessary
//!   (hashing for duplicate detection) and never leave the device.
//!
//! - **Safety classifier refuses to touch what matters**. Dotfiles,
//!   SSH/GPG keys, source repositories, config databases, and user-
//!   supplied protected paths are all off-limits by default.
//!
//! - **Dry-run by default**. Every operation produces a
//!   [`plan::CleanupPlan`] that must be explicitly applied. Deletion
//!   requires a confirmation token per batch.
//!
//! - **No destructive crypto built in**. Forensic-grade destruction
//!   is Purge's job. Tidy's supported actions are review, move to
//!   trash, and simple `unlink(2)`. The Atrium frontend is where
//!   per-item delegation to Purge is wired up.

pub mod action;
pub mod age_analyzer;
pub mod cleaners;
pub mod dedup;
pub mod environment;
pub mod error;
pub mod importance;
pub mod plan;
pub mod scanner;
pub mod size_analyzer;

pub use error::{Result, TidyError};
pub use importance::{Importance, ImportanceClassifier};
pub use scanner::{FileEntry, Scanner, ScanOptions, ScanReport};
