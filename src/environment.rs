//! Environment detection — virtualization, filesystem, OS.
//!
//! Used by the UI to warn the user when traditional secure-delete
//! guarantees (multi-pass overwrite) are not meaningful on the current
//! host — typically on VPS / SSD / copy-on-write filesystems.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Detected virtualization state of the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Virtualization {
    None,
    Kvm,
    Xen,
    Vmware,
    VirtualBox,
    HyperV,
    Qemu,
    LxcContainer,
    DockerContainer,
    Unknown,
}

impl Virtualization {
    pub fn label(&self) -> &'static str {
        match self {
            Virtualization::None => "bare metal",
            Virtualization::Kvm => "KVM",
            Virtualization::Xen => "Xen",
            Virtualization::Vmware => "VMware",
            Virtualization::VirtualBox => "VirtualBox",
            Virtualization::HyperV => "Hyper-V",
            Virtualization::Qemu => "QEMU",
            Virtualization::LxcContainer => "LXC container",
            Virtualization::DockerContainer => "Docker container",
            Virtualization::Unknown => "virtualized (unknown type)",
        }
    }

    pub fn is_virtualized(&self) -> bool {
        !matches!(self, Virtualization::None)
    }
}

/// Broad filesystem category for the working path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageClass {
    BareMetalHdd,
    BareMetalSsd,
    CopyOnWrite,
    Network,
    Unknown,
}

impl StorageClass {
    pub fn label(&self) -> &'static str {
        match self {
            StorageClass::BareMetalHdd => "bare-metal HDD",
            StorageClass::BareMetalSsd => "SSD",
            StorageClass::CopyOnWrite => "copy-on-write filesystem",
            StorageClass::Network => "network / distributed storage",
            StorageClass::Unknown => "unknown",
        }
    }
}

/// Overall report the UI consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentReport {
    pub virtualization: Virtualization,
    pub storage_class: StorageClass,
    pub overwrite_effective: bool,
    pub crypto_shred_recommended: bool,
    pub notes: Vec<String>,
}

impl EnvironmentReport {
    /// Produce a human-readable warning banner suitable for UI display.
    pub fn warning_banner(&self) -> Option<String> {
        if self.overwrite_effective {
            return None;
        }
        Some(format!(
            "Multi-pass secure delete is not meaningful on this system ({}, {}). Use crypto-shred instead.",
            self.virtualization.label(),
            self.storage_class.label(),
        ))
    }
}

/// Detect the current environment.
pub fn detect() -> EnvironmentReport {
    let virt = detect_virtualization();
    let storage = detect_storage_class();
    let overwrite_effective = matches!(
        (&virt, &storage),
        (Virtualization::None, StorageClass::BareMetalHdd)
    );
    let crypto_shred_recommended = !overwrite_effective;

    let mut notes = Vec::new();
    if virt.is_virtualized() {
        notes.push(format!(
            "Running under {}. Hypervisor snapshots and provider backups are outside this tool's reach.",
            virt.label()
        ));
    }
    match storage {
        StorageClass::BareMetalSsd => notes.push(
            "SSD wear-leveling means overwrites may land on different physical cells. Only the controller can truly erase a cell.".into(),
        ),
        StorageClass::CopyOnWrite => notes.push(
            "Copy-on-write filesystems allocate new blocks on overwrite; old blocks persist in snapshots and free space.".into(),
        ),
        StorageClass::Network => notes.push(
            "Network/distributed storage is managed by a backend that does not honor overwrite semantics.".into(),
        ),
        _ => {}
    }

    EnvironmentReport {
        virtualization: virt,
        storage_class: storage,
        overwrite_effective,
        crypto_shred_recommended,
        notes,
    }
}

fn detect_virtualization() -> Virtualization {
    // 1. systemd-detect-virt (most reliable, read dmi/cpuid)
    if let Ok(out) = std::process::Command::new("systemd-detect-virt").output()
        && out.status.success()
    {
        let tag = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return match tag.as_str() {
            "none" => Virtualization::None,
            "kvm" => Virtualization::Kvm,
            "xen" => Virtualization::Xen,
            "vmware" => Virtualization::Vmware,
            "oracle" => Virtualization::VirtualBox,
            "microsoft" => Virtualization::HyperV,
            "qemu" => Virtualization::Qemu,
            "lxc" | "lxc-libvirt" => Virtualization::LxcContainer,
            "docker" => Virtualization::DockerContainer,
            "" => Virtualization::None,
            _ => Virtualization::Unknown,
        };
    }

    // 2. Fallback: look for classic hints without reading user files.
    if Path::new("/.dockerenv").exists() {
        return Virtualization::DockerContainer;
    }
    if Path::new("/sys/hypervisor/type").exists() {
        return Virtualization::Unknown;
    }
    Virtualization::None
}

fn detect_storage_class() -> StorageClass {
    // Look at /proc/mounts for the root filesystem type.
    // We only read the structured procfs file, not user content.
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return StorageClass::Unknown;
    };

    let mut root_fs: Option<String> = None;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "/" {
            root_fs = Some(fields[2].to_string());
            break;
        }
    }

    match root_fs.as_deref() {
        Some("btrfs") | Some("zfs") | Some("bcachefs") => StorageClass::CopyOnWrite,
        Some("nfs") | Some("nfs4") | Some("cifs") | Some("ceph") => StorageClass::Network,
        Some("ext4") | Some("xfs") | Some("ext3") | Some("ext2") => classify_root_block_device(),
        _ => StorageClass::Unknown,
    }
}

fn classify_root_block_device() -> StorageClass {
    // Try /sys/block/{dev}/queue/rotational — "0" means SSD, "1" means spinning.
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return StorageClass::Unknown;
    };
    let mut any_rotational = false;
    let mut any_ssd = false;
    for entry in entries.flatten() {
        let rot = entry.path().join("queue").join("rotational");
        if let Ok(s) = std::fs::read_to_string(&rot) {
            match s.trim() {
                "1" => any_rotational = true,
                "0" => any_ssd = true,
                _ => {}
            }
        }
    }
    match (any_rotational, any_ssd) {
        (true, false) => StorageClass::BareMetalHdd,
        (false, true) => StorageClass::BareMetalSsd,
        // Mixed or unknown → assume SSD for safety (most common, overwrite isn't guaranteed).
        _ => StorageClass::BareMetalSsd,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtualization_label_nonempty() {
        for v in [
            Virtualization::None,
            Virtualization::Kvm,
            Virtualization::Xen,
            Virtualization::Vmware,
            Virtualization::VirtualBox,
            Virtualization::HyperV,
            Virtualization::Qemu,
            Virtualization::LxcContainer,
            Virtualization::DockerContainer,
            Virtualization::Unknown,
        ] {
            assert!(!v.label().is_empty());
        }
    }

    #[test]
    fn test_is_virtualized() {
        assert!(!Virtualization::None.is_virtualized());
        assert!(Virtualization::Kvm.is_virtualized());
        assert!(Virtualization::DockerContainer.is_virtualized());
    }

    #[test]
    fn test_storage_class_label_nonempty() {
        for s in [
            StorageClass::BareMetalHdd,
            StorageClass::BareMetalSsd,
            StorageClass::CopyOnWrite,
            StorageClass::Network,
            StorageClass::Unknown,
        ] {
            assert!(!s.label().is_empty());
        }
    }

    #[test]
    fn test_warning_banner_suppressed_on_bare_metal() {
        let report = EnvironmentReport {
            virtualization: Virtualization::None,
            storage_class: StorageClass::BareMetalHdd,
            overwrite_effective: true,
            crypto_shred_recommended: false,
            notes: Vec::new(),
        };
        assert!(report.warning_banner().is_none());
    }

    #[test]
    fn test_warning_banner_shows_on_ssd() {
        let report = EnvironmentReport {
            virtualization: Virtualization::None,
            storage_class: StorageClass::BareMetalSsd,
            overwrite_effective: false,
            crypto_shred_recommended: true,
            notes: vec!["SSD warning".into()],
        };
        let banner = report.warning_banner().unwrap();
        assert!(banner.contains("SSD"));
    }

    #[test]
    fn test_detect_runs_without_panicking() {
        // On any host we at least get a report — values depend on machine.
        let _ = detect();
    }

    #[test]
    fn test_crypto_shred_recommended_when_overwrite_ineffective() {
        let report = EnvironmentReport {
            virtualization: Virtualization::Kvm,
            storage_class: StorageClass::CopyOnWrite,
            overwrite_effective: false,
            crypto_shred_recommended: true,
            notes: vec![],
        };
        assert!(report.crypto_shred_recommended);
    }
}
