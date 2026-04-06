//! # PlausiDen-Tidy
//!
//! Smart filesystem cleaner with importance-aware safety and optional
//! secure-wipe delegation to PlausiDen-Purge.
//!
//! ## Design principles
//!
//! - **Metadata-first**. The scanner reads `stat` metadata, not file
//!   contents. Content reads happen only where strictly necessary
//!   (hashing for duplicate detection) and never cross the device
//!   boundary.
//!
//! - **Safety classifier refuses to touch what matters**. Dotfiles,
//!   SSH/GPG keys, source repositories, config databases, and user-
//!   supplied protected paths are all off-limits by default.
//!
//! - **Dry-run by default**. Every operation produces a
//!   [`plan::CleanupPlan`] that must be explicitly applied. Deletion
//!   requires a confirmation token per batch.
//!
//! - **Two delete paths**. [`action::SimpleDelete`] calls `unlink(2)`;
//!   when the `purge` feature is enabled, [`action::PurgeDelete`]
//!   delegates to PlausiDen-Purge for secure multi-pass wipe.

pub mod action;
pub mod age_analyzer;
pub mod dedup;
pub mod environment;
pub mod error;
#[cfg(feature = "gui")]
pub mod gui;
pub mod importance;
pub mod plan;
pub mod scanner;
pub mod size_analyzer;

pub use error::{Result, TidyError};
pub use importance::{Importance, ImportanceClassifier};
pub use scanner::{FileEntry, Scanner, ScanOptions, ScanReport};
