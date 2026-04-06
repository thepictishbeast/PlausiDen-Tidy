//! Error types for plausiden-tidy.

use std::path::PathBuf;
use thiserror::Error;

/// Top-level error for all Tidy operations.
#[derive(Debug, Error)]
pub enum TidyError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("path {0} is refused by the importance classifier")]
    PathProtected(PathBuf),

    #[error("path {0} is not a file")]
    NotAFile(PathBuf),

    #[error("path {0} does not exist")]
    NotFound(PathBuf),

    #[error("permission denied for {0}")]
    PermissionDenied(PathBuf),

    #[error("confirmation token mismatch (expected {expected}, got {got})")]
    ConfirmationMismatch { expected: String, got: String },

    #[error("plan has no pending actions")]
    EmptyPlan,

    #[error("purge backend unavailable (feature `purge` not enabled)")]
    PurgeUnavailable,

    #[error("serialization error: {0}")]
    Serde(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, TidyError>;

impl TidyError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl From<serde_json::Error> for TidyError {
    fn from(e: serde_json::Error) -> Self {
        TidyError::Serde(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_constructor() {
        let e = TidyError::io(
            "/tmp/foo",
            std::io::Error::new(std::io::ErrorKind::NotFound, "nope"),
        );
        assert!(matches!(e, TidyError::Io { .. }));
    }

    #[test]
    fn test_path_protected_display() {
        let e = TidyError::PathProtected("/home/user/.ssh/id_rsa".into());
        assert!(e.to_string().contains("refused"));
    }

    #[test]
    fn test_confirmation_mismatch() {
        let e = TidyError::ConfirmationMismatch {
            expected: "abc".into(),
            got: "xyz".into(),
        };
        let s = e.to_string();
        assert!(s.contains("abc") && s.contains("xyz"));
    }

    #[test]
    fn test_empty_plan_error() {
        let e = TidyError::EmptyPlan;
        assert!(e.to_string().contains("pending"));
    }

    #[test]
    fn test_purge_unavailable_error() {
        let e = TidyError::PurgeUnavailable;
        assert!(e.to_string().contains("purge"));
    }
}
