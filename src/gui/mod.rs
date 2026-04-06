//! Desktop GUI for PlausiDen-Tidy.
//!
//! The GUI is the primary interface — every backend capability is
//! reachable from here. The library never deletes on its own; the
//! GUI is the one place where the user reviews candidates, approves
//! individual items, and explicitly confirms a plan before anything
//! happens on disk. Dry-run is the default and is the only mode
//! wired up by default.

pub mod app;
pub mod theme;

pub use app::{Tab, TidyApp};

/// Human-readable byte formatter. Never uses underscores.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

/// Short-form file count e.g. "1.2K files".
pub fn format_count(n: u64) -> String {
    if n < 1_000 {
        format!("{}", n)
    } else if n < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_kilobyte() {
        assert_eq!(format_bytes(1024), "1.00 KB");
    }

    #[test]
    fn test_format_bytes_megabyte() {
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn test_format_bytes_gigabyte() {
        assert_eq!(format_bytes(1024u64.pow(3)), "1.00 GB");
    }

    #[test]
    fn test_format_count_small() {
        assert_eq!(format_count(42), "42");
    }

    #[test]
    fn test_format_count_thousands() {
        assert_eq!(format_count(1_500), "1.5K");
    }

    #[test]
    fn test_format_count_millions() {
        assert_eq!(format_count(2_500_000), "2.5M");
    }
}
