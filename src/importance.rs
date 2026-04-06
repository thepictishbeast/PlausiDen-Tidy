//! Importance classifier — safety heuristic that refuses to delete what matters.
//!
//! Given a path, [`ImportanceClassifier`] returns a five-tier
//! [`Importance`] rating. Anything `Critical` or `High` is off-limits by
//! default; `Medium` is safe to suggest but requires confirmation;
//! `Low` and `Trash` are first-class cleanup targets.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Tier of safety-critical importance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Importance {
    /// Must never be touched. Keys, password stores, source control, etc.
    Critical,
    /// Important enough that deletion should be refused by default.
    High,
    /// Probably user data — allowed but requires confirmation.
    Medium,
    /// Caches, temp files, downloads the user may not need.
    Low,
    /// Obvious junk: editor backups, crash dumps, trash bin entries.
    Trash,
}

impl Importance {
    /// Is this tier eligible for *any* delete action by default?
    pub fn is_deletable(&self) -> bool {
        matches!(self, Importance::Low | Importance::Trash | Importance::Medium)
    }

    /// Does this tier require an explicit per-item confirmation?
    pub fn requires_confirmation(&self) -> bool {
        !matches!(self, Importance::Trash)
    }
}

/// Rationale tag attached to a classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    DotfileRoot,
    SecurityKey,
    PasswordStore,
    SourceRepository,
    PackageManifest,
    ConfigDatabase,
    BrowserProfile,
    MediaLibrary,
    Downloads,
    CacheDirectory,
    TempDirectory,
    EditorBackup,
    CoreDump,
    TrashBin,
    UserAllowlist,
    UserBlocklist,
    None,
}

/// A classifier decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub path: PathBuf,
    pub importance: Importance,
    pub reason: Reason,
}

/// Path-based importance classifier.
pub struct ImportanceClassifier {
    extra_critical: Vec<PathBuf>,
    extra_trash_exts: Vec<String>,
    home: Option<PathBuf>,
}

impl ImportanceClassifier {
    pub fn new() -> Self {
        Self {
            extra_critical: Vec::new(),
            extra_trash_exts: Vec::new(),
            home: home_dir(),
        }
    }

    /// Add an extra user-supplied "never touch" path.
    pub fn protect(&mut self, path: impl Into<PathBuf>) {
        self.extra_critical.push(path.into());
    }

    /// Add an extra extension (no leading dot) that is considered trash.
    pub fn add_trash_extension(&mut self, ext: impl Into<String>) {
        self.extra_trash_exts.push(ext.into().to_lowercase());
    }

    /// Classify a single path.
    pub fn classify(&self, path: &Path) -> Verdict {
        let s = path.to_string_lossy().to_string();

        // User-supplied blocklist wins over everything.
        for extra in &self.extra_critical {
            if path.starts_with(extra) {
                return Verdict {
                    path: path.to_path_buf(),
                    importance: Importance::Critical,
                    reason: Reason::UserBlocklist,
                };
            }
        }

        if let Some(home) = &self.home {
            let home_str = home.to_string_lossy();
            let under = |suffix: &str| -> bool {
                s.starts_with(&format!("{}/{}", home_str, suffix))
            };

            if under(".ssh") || under(".gnupg") {
                return Verdict {
                    path: path.to_path_buf(),
                    importance: Importance::Critical,
                    reason: Reason::SecurityKey,
                };
            }
            if under(".password-store") || under(".pki") {
                return Verdict {
                    path: path.to_path_buf(),
                    importance: Importance::Critical,
                    reason: Reason::PasswordStore,
                };
            }
            if under("Development")
                || under("Projects")
                || under("src")
                || under("code")
                || under("workspace")
                || under("Documents/Code")
            {
                return Verdict {
                    path: path.to_path_buf(),
                    importance: Importance::Critical,
                    reason: Reason::SourceRepository,
                };
            }
        }

        // Source control markers anywhere: .git, .hg, .svn
        for comp in path.components() {
            let c = comp.as_os_str().to_string_lossy();
            if c == ".git" || c == ".hg" || c == ".svn" || c == ".jj" {
                return Verdict {
                    path: path.to_path_buf(),
                    importance: Importance::Critical,
                    reason: Reason::SourceRepository,
                };
            }
        }

        let file_name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let lower = file_name.to_lowercase();

        let manifests = [
            "cargo.toml",
            "cargo.lock",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "pyproject.toml",
            "requirements.txt",
            "go.mod",
            "go.sum",
            "gemfile",
            "gemfile.lock",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "mix.exs",
            "stack.yaml",
            "makefile",
            "cmakelists.txt",
            "dockerfile",
        ];
        if manifests.iter().any(|m| lower == *m) {
            return Verdict {
                path: path.to_path_buf(),
                importance: Importance::Critical,
                reason: Reason::PackageManifest,
            };
        }

        // Extension-based trash detection.
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            let default_trash = ["bak", "swp", "swo", "tmp", "~", "orig", "log"];
            if default_trash.contains(&ext_lower.as_str())
                || self.extra_trash_exts.iter().any(|e| e == &ext_lower)
            {
                return Verdict {
                    path: path.to_path_buf(),
                    importance: Importance::Trash,
                    reason: Reason::EditorBackup,
                };
            }
            if ext_lower == "core" || ext_lower == "dmp" {
                return Verdict {
                    path: path.to_path_buf(),
                    importance: Importance::Trash,
                    reason: Reason::CoreDump,
                };
            }
        }

        if lower.ends_with('~') {
            return Verdict {
                path: path.to_path_buf(),
                importance: Importance::Trash,
                reason: Reason::EditorBackup,
            };
        }

        // Directory heuristics.
        if s.contains("/.cache/") || s.contains("/.mozilla/firefox/") && s.contains("Cache") {
            return Verdict {
                path: path.to_path_buf(),
                importance: Importance::Low,
                reason: Reason::CacheDirectory,
            };
        }
        if s.contains("/Trash/") || s.contains("/.local/share/Trash/") {
            return Verdict {
                path: path.to_path_buf(),
                importance: Importance::Trash,
                reason: Reason::TrashBin,
            };
        }
        if s.contains("/Downloads/") {
            return Verdict {
                path: path.to_path_buf(),
                importance: Importance::Low,
                reason: Reason::Downloads,
            };
        }
        if s.starts_with("/tmp/") || s.contains("/tmp/") {
            return Verdict {
                path: path.to_path_buf(),
                importance: Importance::Low,
                reason: Reason::TempDirectory,
            };
        }

        // Browser profile cores: places.sqlite, cookies.sqlite, key4.db, etc.
        let profile_critical = [
            "places.sqlite",
            "cookies.sqlite",
            "key4.db",
            "logins.json",
            "cert9.db",
            "bookmarks.html",
        ];
        if profile_critical.contains(&lower.as_str()) {
            return Verdict {
                path: path.to_path_buf(),
                importance: Importance::High,
                reason: Reason::BrowserProfile,
            };
        }

        // Default: medium — user data, allowed but requires confirmation.
        Verdict {
            path: path.to_path_buf(),
            importance: Importance::Medium,
            reason: Reason::None,
        }
    }
}

impl Default for ImportanceClassifier {
    fn default() -> Self {
        Self::new()
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_key_is_critical() {
        let mut c = ImportanceClassifier::new();
        c.home = Some(PathBuf::from("/home/u"));
        let v = c.classify(Path::new("/home/u/.ssh/id_rsa"));
        assert_eq!(v.importance, Importance::Critical);
        assert_eq!(v.reason, Reason::SecurityKey);
    }

    #[test]
    fn test_gpg_dir_is_critical() {
        let mut c = ImportanceClassifier::new();
        c.home = Some(PathBuf::from("/home/u"));
        let v = c.classify(Path::new("/home/u/.gnupg/secring.gpg"));
        assert_eq!(v.importance, Importance::Critical);
    }

    #[test]
    fn test_source_tree_is_critical() {
        let mut c = ImportanceClassifier::new();
        c.home = Some(PathBuf::from("/home/u"));
        let v = c.classify(Path::new("/home/u/Development/proj/main.rs"));
        assert_eq!(v.importance, Importance::Critical);
        assert_eq!(v.reason, Reason::SourceRepository);
    }

    #[test]
    fn test_git_dir_anywhere_is_critical() {
        let c = ImportanceClassifier::new();
        let v = c.classify(Path::new("/var/random/.git/HEAD"));
        assert_eq!(v.importance, Importance::Critical);
    }

    #[test]
    fn test_cargo_toml_is_manifest() {
        let c = ImportanceClassifier::new();
        let v = c.classify(Path::new("/any/path/Cargo.toml"));
        assert_eq!(v.importance, Importance::Critical);
        assert_eq!(v.reason, Reason::PackageManifest);
    }

    #[test]
    fn test_editor_backup_is_trash() {
        let c = ImportanceClassifier::new();
        let v = c.classify(Path::new("/home/u/notes.txt.bak"));
        assert_eq!(v.importance, Importance::Trash);
    }

    #[test]
    fn test_core_dump_is_trash() {
        let c = ImportanceClassifier::new();
        let v = c.classify(Path::new("/home/u/crash.core"));
        assert_eq!(v.importance, Importance::Trash);
    }

    #[test]
    fn test_downloads_is_low() {
        let c = ImportanceClassifier::new();
        let v = c.classify(Path::new("/home/u/Downloads/installer.iso"));
        assert_eq!(v.importance, Importance::Low);
    }

    #[test]
    fn test_cache_is_low() {
        let c = ImportanceClassifier::new();
        let v = c.classify(Path::new("/home/u/.cache/thumbnails/foo.png"));
        assert_eq!(v.importance, Importance::Low);
    }

    #[test]
    fn test_places_sqlite_is_high() {
        let c = ImportanceClassifier::new();
        let v = c.classify(Path::new("/home/u/.mozilla/firefox/x/places.sqlite"));
        assert_eq!(v.importance, Importance::High);
    }

    #[test]
    fn test_unknown_defaults_to_medium() {
        let c = ImportanceClassifier::new();
        let v = c.classify(Path::new("/home/u/Documents/notes.txt"));
        assert_eq!(v.importance, Importance::Medium);
    }

    #[test]
    fn test_user_blocklist_wins() {
        let mut c = ImportanceClassifier::new();
        c.protect("/home/u/secret");
        let v = c.classify(Path::new("/home/u/secret/whatever.txt"));
        assert_eq!(v.importance, Importance::Critical);
        assert_eq!(v.reason, Reason::UserBlocklist);
    }

    #[test]
    fn test_trash_tier_no_confirmation() {
        assert!(!Importance::Trash.requires_confirmation());
        assert!(Importance::Medium.requires_confirmation());
    }

    #[test]
    fn test_critical_not_deletable() {
        assert!(!Importance::Critical.is_deletable());
        assert!(Importance::Trash.is_deletable());
    }
}
