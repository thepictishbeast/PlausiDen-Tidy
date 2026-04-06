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
                // Tidy deliberately does not implement forensic-grade
                // destruction. Callers that want SecurePurge must
                // delegate to PlausiDen-Purge — the Atrium frontend
                // wires up that delegation.
                Err(TidyError::PurgeUnavailable)
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

/// Pick a destination filename inside `trash_files` that does not
/// already exist. If `name` is free, use it; otherwise append
/// `.1`, `.2`, … until we find an empty slot.
///
/// BUG ASSUMPTION: the filesystem changes between calls. A TOCTOU
/// race between the existence check here and the subsequent rename
/// is theoretically possible but would require another trash client
/// creating a file in the split-second window.
fn unique_trash_dest(trash_files: &Path, name: &std::ffi::OsStr) -> PathBuf {
    let candidate = trash_files.join(name);
    if !candidate.exists() {
        return candidate;
    }
    // Up to 10_000 collision attempts before giving up with a random
    // suffix derived from the wall clock. In practice the first few
    // attempts always succeed.
    for i in 1..10_000 {
        let stem = format!("{}.{}", name.to_string_lossy(), i);
        let candidate = trash_files.join(&stem);
        if !candidate.exists() {
            return candidate;
        }
    }
    // Fallback: timestamp suffix so we never return an existing path.
    let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    trash_files.join(format!("{}.{}", name.to_string_lossy(), ts))
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
    // XDG Trash spec: move to $XDG_DATA_HOME/Trash/files/ and drop a
    // corresponding .trashinfo file into $XDG_DATA_HOME/Trash/info/.
    //
    // REGRESSION-GUARD: an earlier version used fs::rename(path, dest)
    // directly, which silently clobbered any existing file at `dest`.
    // Two files with the same name from different source dirs would
    // lose the first one on the second trash move. Fixed by finding
    // the first unique destination name and never overwriting.
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        TidyError::io(
            path.to_path_buf(),
            std::io::Error::other("HOME not set; cannot locate trash"),
        )
    })?;
    let trash_base = home.join(".local/share/Trash");
    let trash_files = trash_base.join("files");
    let trash_info = trash_base.join("info");
    std::fs::create_dir_all(&trash_files)
        .map_err(|e| TidyError::io(trash_files.clone(), e))?;
    std::fs::create_dir_all(&trash_info)
        .map_err(|e| TidyError::io(trash_info.clone(), e))?;

    let name = path
        .file_name()
        .map(|s| s.to_owned())
        .ok_or_else(|| TidyError::NotAFile(path.to_path_buf()))?;

    // Pick a unique destination name. If `name` is free, use it.
    // Otherwise append `.1`, `.2`, … until we find an unused slot.
    let dest = unique_trash_dest(&trash_files, &name);

    // Move the file. The uniquification above guarantees dest does
    // not exist at this instant; a TOCTOU with concurrent trash
    // clients is possible but extremely unlikely.
    std::fs::rename(path, &dest)
        .map_err(|e| TidyError::io(path.to_path_buf(), e))?;

    // Write the .trashinfo sidecar per the FreeDesktop Trash spec.
    // A malformed sidecar is not a hard error — the file is already
    // in the trash directory at this point and a cleanup is the
    // user's ordinary "empty trash" action.
    let trashinfo_name = dest
        .file_name()
        .map(|s| format!("{}.trashinfo", s.to_string_lossy()))
        .unwrap_or_else(|| "unknown.trashinfo".to_string());
    let trashinfo_path = trash_info.join(trashinfo_name);
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let info_body = format!(
        "[Trash Info]\nPath={}\nDeletionDate={}\n",
        path.display(),
        now
    );
    let _ = std::fs::write(&trashinfo_path, info_body);

    Ok(ActionResult {
        path: path.to_path_buf(),
        kind: ActionKind::MoveToTrash,
        success: true,
        message: format!("moved to {}", dest.display()),
        bytes_reclaimed: size,
    })
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

    // REGRESSION-GUARD: the earlier move_to_trash used fs::rename
    // which silently clobbered collisions. Two files named the same
    // from different source directories would lose the first one.
    #[test]
    fn test_unique_trash_dest_avoids_collision() {
        let dir = std::env::temp_dir().join(format!(
            "tidy-trash-collision-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Pre-populate with a collision.
        let existing = dir.join("foo.txt");
        std::fs::write(&existing, b"existing").unwrap();

        let first = unique_trash_dest(&dir, std::ffi::OsStr::new("foo.txt"));
        // Should NOT equal the existing path.
        assert_ne!(first, existing);
        assert!(first.to_string_lossy().contains("foo.txt.1"));

        // Create the .1 suffix to force the next call to pick .2.
        std::fs::write(&first, b"first").unwrap();
        let second = unique_trash_dest(&dir, std::ffi::OsStr::new("foo.txt"));
        assert_ne!(second, first);
        assert_ne!(second, existing);
        assert!(second.to_string_lossy().contains("foo.txt.2"));

        // The original file is untouched.
        let existing_contents = std::fs::read(&existing).unwrap();
        assert_eq!(existing_contents, b"existing");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_unique_trash_dest_no_collision_returns_plain_name() {
        let dir = std::env::temp_dir().join(format!(
            "tidy-trash-clean-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let result = unique_trash_dest(&dir, std::ffi::OsStr::new("new.txt"));
        assert_eq!(result, dir.join("new.txt"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_secure_purge_always_delegates() {
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
