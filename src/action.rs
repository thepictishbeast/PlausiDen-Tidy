//! File actions — the *only* code paths that can remove a file.
//!
//! Nothing in this module is invoked automatically. Actions are built
//! into a [`crate::plan::CleanupPlan`], reviewed by the user, and
//! executed only after an explicit, per-batch confirmation. The library
//! never calls [`ActionKind::SimpleDelete::execute`] or the purge
//! delegation path on its own — that is always the frontend's decision.

use crate::error::{Result, TidyError};
use crate::importance::{Importance, ImportanceClassifier, Verdict};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Kind of action a plan entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionKind {
    /// Ordinary `unlink(2)`. Fast, reversible from the filesystem's
    /// perspective only if the file is in a trash bin — otherwise gone.
    SimpleDelete,
    /// Move to the XDG freedesktop trash directory (safer default).
    MoveToTrash,
    /// Delegate to PlausiDen-Purge for multi-pass overwrite. Intended
    /// for forensic-grade destruction; enabled behind the `purge`
    /// feature flag.
    SecurePurge,
    /// A no-op placeholder used when the user wants a plan entry to
    /// be recorded but not acted upon.
    Review,
}

impl ActionKind {
    pub fn description(&self) -> &'static str {
        match self {
            ActionKind::SimpleDelete => "delete (unlink)",
            ActionKind::MoveToTrash => "move to trash",
            ActionKind::SecurePurge => "secure purge (delegate to PlausiDen-Purge)",
            ActionKind::Review => "mark for review",
        }
    }

    pub fn is_destructive(&self) -> bool {
        matches!(
            self,
            ActionKind::SimpleDelete | ActionKind::SecurePurge
        )
    }
}

/// A single action on a single file, with its classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanAction {
    pub path: PathBuf,
    pub size: u64,
    pub kind: ActionKind,
    pub verdict: Verdict,
    /// The user must explicitly toggle this before the action is run.
    pub approved: bool,
    /// Notes (e.g. "duplicate of /foo/bar", "age 400 days").
    pub notes: Vec<String>,
}

impl PlanAction {
    pub fn new(path: PathBuf, size: u64, kind: ActionKind, verdict: Verdict) -> Self {
        Self {
            path,
            size,
            kind,
            verdict,
            approved: false,
            notes: Vec::new(),
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn approve(&mut self) {
        self.approved = true;
    }

    pub fn unapprove(&mut self) {
        self.approved = false;
    }

    pub fn is_safe_to_execute(&self, classifier: &ImportanceClassifier) -> bool {
        if !self.approved {
            return false;
        }
        // Re-classify at execution time so a user-supplied blocklist
        // update between plan construction and execution is honored.
        let fresh = classifier.classify(&self.path);
        fresh.importance.is_deletable() && fresh.importance != Importance::Critical
    }
}

/// Outcome of attempting to execute a single action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub path: PathBuf,
    pub kind: ActionKind,
    pub success: bool,
    pub message: String,
    pub bytes_reclaimed: u64,
}

/// Executor trait. The default implementation performs the action on
/// disk; tests supply a mock executor that records the call without
/// touching the filesystem.
pub trait ActionExecutor {
    fn execute(&mut self, action: &PlanAction) -> Result<ActionResult>;
}

/// Default on-disk executor. Only used after the user confirms.
pub struct FsExecutor {
    /// Whether a dry-run only (no actual deletion).
    pub dry_run: bool,
}

impl FsExecutor {
    pub fn dry() -> Self {
        Self { dry_run: true }
    }

    pub fn real() -> Self {
        Self { dry_run: false }
    }
}

impl ActionExecutor for FsExecutor {
    fn execute(&mut self, action: &PlanAction) -> Result<ActionResult> {
        if !action.approved {
            return Ok(ActionResult {
                path: action.path.clone(),
                kind: action.kind,
                success: false,
                message: "action not approved".into(),
                bytes_reclaimed: 0,
            });
        }

        if self.dry_run {
            return Ok(ActionResult {
                path: action.path.clone(),
                kind: action.kind,
                success: true,
                message: format!("DRY-RUN: would {}", action.kind.description()),
                bytes_reclaimed: action.size,
            });
        }

        match action.kind {
            ActionKind::SimpleDelete => remove_file(&action.path, action.size),
            ActionKind::MoveToTrash => move_to_trash(&action.path, action.size),
            ActionKind::SecurePurge => {
                #[cfg(feature = "purge")]
                {
                    purge_delegate(&action.path, action.size)
                }
                #[cfg(not(feature = "purge"))]
                {
                    Err(TidyError::PurgeUnavailable)
                }
            }
            ActionKind::Review => Ok(ActionResult {
                path: action.path.clone(),
                kind: ActionKind::Review,
                success: true,
                message: "marked for review".into(),
                bytes_reclaimed: 0,
            }),
        }
    }
}

fn remove_file(path: &Path, size: u64) -> Result<ActionResult> {
    match std::fs::remove_file(path) {
        Ok(_) => Ok(ActionResult {
            path: path.to_path_buf(),
            kind: ActionKind::SimpleDelete,
            success: true,
            message: "deleted".into(),
            bytes_reclaimed: size,
        }),
        Err(e) => Err(TidyError::io(path.to_path_buf(), e)),
    }
}

fn move_to_trash(path: &Path, size: u64) -> Result<ActionResult> {
    // XDG Trash spec: move to $XDG_DATA_HOME/Trash/files/
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        TidyError::io(
            path.to_path_buf(),
            std::io::Error::other("HOME not set; cannot locate trash"),
        )
    })?;
    let trash_dir = home.join(".local/share/Trash/files");
    std::fs::create_dir_all(&trash_dir).map_err(|e| TidyError::io(trash_dir.clone(), e))?;
    let name = path
        .file_name()
        .map(|s| s.to_owned())
        .ok_or_else(|| TidyError::NotAFile(path.to_path_buf()))?;
    let dest = trash_dir.join(name);
    std::fs::rename(path, &dest).map_err(|e| TidyError::io(path.to_path_buf(), e))?;
    Ok(ActionResult {
        path: path.to_path_buf(),
        kind: ActionKind::MoveToTrash,
        success: true,
        message: format!("moved to {}", dest.display()),
        bytes_reclaimed: size,
    })
}

#[cfg(feature = "purge")]
fn purge_delegate(path: &Path, size: u64) -> Result<ActionResult> {
    // Real implementation will shell out to `plausiden-purge` or link it
    // as a path dependency. For now this is a stub returning a clear
    // "not yet implemented" so the frontend knows the delegation hook
    // is present even if the backend isn't wired.
    let _ = (path, size);
    Err(TidyError::PurgeUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::importance::Reason;

    fn sample_verdict(path: &str, level: Importance) -> Verdict {
        Verdict {
            path: PathBuf::from(path),
            importance: level,
            reason: Reason::None,
        }
    }

    #[test]
    fn test_unapproved_actions_refuse_execution() {
        let mut exec = FsExecutor::dry();
        let a = PlanAction::new(
            PathBuf::from("/tmp/x"),
            100,
            ActionKind::SimpleDelete,
            sample_verdict("/tmp/x", Importance::Low),
        );
        let r = exec.execute(&a).unwrap();
        assert!(!r.success);
    }

    #[test]
    fn test_approved_dry_run_reports_would_delete() {
        let mut exec = FsExecutor::dry();
        let mut a = PlanAction::new(
            PathBuf::from("/tmp/x"),
            100,
            ActionKind::SimpleDelete,
            sample_verdict("/tmp/x", Importance::Low),
        );
        a.approve();
        let r = exec.execute(&a).unwrap();
        assert!(r.success);
        assert!(r.message.contains("DRY-RUN"));
    }

    #[test]
    fn test_action_kind_is_destructive() {
        assert!(ActionKind::SimpleDelete.is_destructive());
        assert!(ActionKind::SecurePurge.is_destructive());
        assert!(!ActionKind::Review.is_destructive());
        assert!(!ActionKind::MoveToTrash.is_destructive());
    }

    #[test]
    fn test_is_safe_to_execute_rejects_unapproved() {
        let classifier = ImportanceClassifier::new();
        let a = PlanAction::new(
            PathBuf::from("/tmp/x.bak"),
            10,
            ActionKind::SimpleDelete,
            sample_verdict("/tmp/x.bak", Importance::Trash),
        );
        assert!(!a.is_safe_to_execute(&classifier));
    }

    #[test]
    fn test_is_safe_to_execute_rejects_critical_path() {
        let classifier = ImportanceClassifier::new();
        let mut a = PlanAction::new(
            PathBuf::from("/any/Cargo.toml"),
            10,
            ActionKind::SimpleDelete,
            sample_verdict("/any/Cargo.toml", Importance::Trash),
        );
        a.approve();
        // Re-classification at execute-time catches this.
        assert!(!a.is_safe_to_execute(&classifier));
    }

    #[test]
    fn test_approve_unapprove_round_trip() {
        let mut a = PlanAction::new(
            PathBuf::from("/tmp/x"),
            1,
            ActionKind::SimpleDelete,
            sample_verdict("/tmp/x", Importance::Low),
        );
        a.approve();
        assert!(a.approved);
        a.unapprove();
        assert!(!a.approved);
    }

    #[test]
    fn test_review_action_is_noop() {
        let mut exec = FsExecutor::dry();
        let mut a = PlanAction::new(
            PathBuf::from("/tmp/x"),
            0,
            ActionKind::Review,
            sample_verdict("/tmp/x", Importance::High),
        );
        a.approve();
        let r = exec.execute(&a).unwrap();
        assert!(r.success);
    }

    #[test]
    fn test_with_note_accumulates() {
        let a = PlanAction::new(
            PathBuf::from("/tmp/x"),
            0,
            ActionKind::SimpleDelete,
            sample_verdict("/tmp/x", Importance::Low),
        )
        .with_note("duplicate of /y")
        .with_note("age 900 days");
        assert_eq!(a.notes.len(), 2);
    }

    #[test]
    fn test_action_kind_description_nonempty() {
        assert!(!ActionKind::SimpleDelete.description().is_empty());
        assert!(!ActionKind::SecurePurge.description().is_empty());
    }

    #[cfg(not(feature = "purge"))]
    #[test]
    fn test_purge_without_feature_flag_errors() {
        let mut exec = FsExecutor::real();
        let mut a = PlanAction::new(
            PathBuf::from("/tmp/x"),
            0,
            ActionKind::SecurePurge,
            sample_verdict("/tmp/x", Importance::Low),
        );
        a.approve();
        let r = exec.execute(&a);
        assert!(matches!(r, Err(TidyError::PurgeUnavailable)));
    }
}
