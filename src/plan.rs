//! Cleanup plans — reviewable, serializable batches of pending actions.
//!
//! A [`CleanupPlan`] is the only way actions reach an executor. Plans
//! are built in-memory, serialized to JSON for persistence, reviewed
//! by the user (typically in the UI), and only then committed. The
//! commit step requires a confirmation token the caller constructs
//! from a plan-level digest, so stale plans can't be silently applied.

use crate::action::{ActionExecutor, ActionResult, PlanAction};
#[cfg(test)]
use crate::action::ActionKind;
use crate::error::{Result, TidyError};
use crate::importance::ImportanceClassifier;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A reviewable batch of pending actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupPlan {
    pub id: String,
    pub actions: Vec<PlanAction>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub description: String,
}

impl CleanupPlan {
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            id: new_plan_id(),
            actions: Vec::new(),
            created_at: chrono::Utc::now(),
            description: description.into(),
        }
    }

    pub fn add(&mut self, action: PlanAction) {
        self.actions.push(action);
    }

    pub fn remove_at(&mut self, idx: usize) -> Option<PlanAction> {
        if idx < self.actions.len() {
            Some(self.actions.remove(idx))
        } else {
            None
        }
    }

    pub fn approve_all(&mut self) {
        for a in &mut self.actions {
            a.approve();
        }
    }

    pub fn unapprove_all(&mut self) {
        for a in &mut self.actions {
            a.unapprove();
        }
    }

    pub fn approve_index(&mut self, idx: usize) -> bool {
        if let Some(a) = self.actions.get_mut(idx) {
            a.approve();
            true
        } else {
            false
        }
    }

    pub fn unapprove_index(&mut self, idx: usize) -> bool {
        if let Some(a) = self.actions.get_mut(idx) {
            a.unapprove();
            true
        } else {
            false
        }
    }

    pub fn approved_count(&self) -> usize {
        self.actions.iter().filter(|a| a.approved).count()
    }

    pub fn total_bytes_approved(&self) -> u64 {
        self.actions
            .iter()
            .filter(|a| a.approved)
            .map(|a| a.size)
            .sum()
    }

    pub fn total_bytes(&self) -> u64 {
        self.actions.iter().map(|a| a.size).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Split actions by destructiveness, so the UI can surface reviews
    /// and destructive items separately.
    pub fn split_by_destructiveness(&self) -> (Vec<&PlanAction>, Vec<&PlanAction>) {
        let (destructive, review): (Vec<_>, Vec<_>) = self
            .actions
            .iter()
            .partition(|a| a.kind.is_destructive());
        (destructive, review)
    }

    /// Produce a short digest the user can type back to confirm.
    pub fn confirmation_digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.id.as_bytes());
        for a in &self.actions {
            if a.approved {
                hasher.update(a.path.to_string_lossy().as_bytes());
                hasher.update(&a.size.to_le_bytes());
                hasher.update(&[a.kind as u8]);
            }
        }
        let bytes = hasher.finalize();
        bytes.to_hex().as_str()[..8].to_string()
    }

    /// Commit the plan. The caller must supply the confirmation token
    /// produced by [`CleanupPlan::confirmation_digest`] immediately
    /// before calling this. Mismatch means the plan was mutated since
    /// the user approved it and is refused.
    pub fn commit<E: ActionExecutor>(
        &self,
        executor: &mut E,
        classifier: &ImportanceClassifier,
        confirmation: &str,
    ) -> Result<Vec<ActionResult>> {
        if self.actions.is_empty() {
            return Err(TidyError::EmptyPlan);
        }
        let expected = self.confirmation_digest();
        if confirmation != expected {
            return Err(TidyError::ConfirmationMismatch {
                expected,
                got: confirmation.to_string(),
            });
        }

        let mut results = Vec::new();
        for action in &self.actions {
            if !action.is_safe_to_execute(classifier) {
                results.push(ActionResult {
                    path: action.path.clone(),
                    kind: action.kind,
                    success: false,
                    message: "refused by safety check".into(),
                    bytes_reclaimed: 0,
                });
                continue;
            }
            match executor.execute(action) {
                Ok(r) => results.push(r),
                Err(e) => results.push(ActionResult {
                    path: action.path.clone(),
                    kind: action.kind,
                    success: false,
                    message: e.to_string(),
                    bytes_reclaimed: 0,
                }),
            }
        }
        Ok(results)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        self.actions.iter().map(|a| a.path.clone()).collect()
    }
}

fn new_plan_id() -> String {
    let now = chrono::Utc::now();
    format!(
        "plan-{}-{:08x}",
        now.format("%Y%m%d-%H%M%S"),
        now.timestamp_nanos_opt().unwrap_or(0) as u32
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{ActionResult, FsExecutor};
    use crate::importance::{Importance, Reason, Verdict};

    fn sample_verdict(path: &str, imp: Importance) -> Verdict {
        Verdict {
            path: PathBuf::from(path),
            importance: imp,
            reason: Reason::None,
        }
    }

    fn sample_action(path: &str) -> PlanAction {
        PlanAction::new(
            PathBuf::from(path),
            100,
            ActionKind::SimpleDelete,
            sample_verdict(path, Importance::Low),
        )
    }

    #[test]
    fn test_new_plan_is_empty() {
        let p = CleanupPlan::new("test");
        assert!(p.is_empty());
    }

    #[test]
    fn test_add_action() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/a"));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn test_approve_all() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/a"));
        p.add(sample_action("/tmp/b"));
        p.approve_all();
        assert_eq!(p.approved_count(), 2);
    }

    #[test]
    fn test_unapprove_all() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/a"));
        p.approve_all();
        p.unapprove_all();
        assert_eq!(p.approved_count(), 0);
    }

    #[test]
    fn test_approve_index() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/a"));
        assert!(p.approve_index(0));
        assert!(!p.approve_index(99));
    }

    #[test]
    fn test_total_bytes_only_counts_approved() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/a"));
        p.add(sample_action("/tmp/b"));
        p.approve_index(0);
        assert_eq!(p.total_bytes_approved(), 100);
        assert_eq!(p.total_bytes(), 200);
    }

    #[test]
    fn test_confirmation_digest_changes_with_approvals() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/a"));
        let before = p.confirmation_digest();
        p.approve_all();
        let after = p.confirmation_digest();
        assert_ne!(before, after);
    }

    #[test]
    fn test_commit_refuses_empty_plan() {
        let p = CleanupPlan::new("test");
        let mut exec = FsExecutor::dry();
        let classifier = ImportanceClassifier::new();
        let result = p.commit(&mut exec, &classifier, "deadbeef");
        assert!(matches!(result, Err(TidyError::EmptyPlan)));
    }

    #[test]
    fn test_commit_refuses_bad_confirmation() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/x"));
        p.approve_all();
        let mut exec = FsExecutor::dry();
        let classifier = ImportanceClassifier::new();
        let result = p.commit(&mut exec, &classifier, "nope");
        assert!(matches!(result, Err(TidyError::ConfirmationMismatch { .. })));
    }

    #[test]
    fn test_commit_dry_run_with_correct_confirmation() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/nonexistent-tidy-test"));
        p.approve_all();
        let confirmation = p.confirmation_digest();
        let mut exec = FsExecutor::dry();
        let classifier = ImportanceClassifier::new();
        let results: Vec<ActionResult> =
            p.commit(&mut exec, &classifier, &confirmation).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn test_json_roundtrip() {
        let mut p = CleanupPlan::new("rt");
        p.add(sample_action("/tmp/a"));
        p.approve_all();
        let json = p.to_json().unwrap();
        let parsed = CleanupPlan::from_json(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.approved_count(), 1);
    }

    #[test]
    fn test_split_by_destructiveness() {
        let mut p = CleanupPlan::new("split");
        let mut review = sample_action("/tmp/r");
        review.kind = ActionKind::Review;
        p.add(sample_action("/tmp/delete"));
        p.add(review);
        let (destructive, reviews) = p.split_by_destructiveness();
        assert_eq!(destructive.len(), 1);
        assert_eq!(reviews.len(), 1);
    }

    #[test]
    fn test_remove_at() {
        let mut p = CleanupPlan::new("test");
        p.add(sample_action("/tmp/a"));
        p.add(sample_action("/tmp/b"));
        assert!(p.remove_at(0).is_some());
        assert_eq!(p.len(), 1);
    }
}
