//! PlausiDen-Tidy GUI application.
//!
//! A civil-rights-friendly desktop cleaner. Every backend capability
//! (scan, duplicate detection, age/size analysis, importance
//! classification, action planning, confirmation) is surfaced here
//! with clear visual hierarchy, safe-by-default selections, and an
//! explicit commit step that is locked OFF until the user opts in.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use egui::{Align, Color32, Layout, RichText, ScrollArea, TextEdit, Ui};

use crate::action::{ActionKind, FsExecutor, PlanAction};
use crate::age_analyzer::{AgeAnalyzer, AgeReport};
use crate::dedup::{DedupReport, Deduplicator, DupGroup};
use crate::environment::{self, EnvironmentReport};
use crate::gui::theme::{importance_color, importance_label, Palette};
use crate::gui::format_bytes;
use crate::importance::{Importance, ImportanceClassifier};
use crate::plan::CleanupPlan;
use crate::scanner::{FileEntry, ScanOptions, ScanReport, Scanner};
use crate::size_analyzer::{SizeAnalyzer, SizeReport};

/// Top-level tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Scan,
    Duplicates,
    OldFiles,
    LargeFiles,
    Plan,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Scan,
        Tab::Duplicates,
        Tab::OldFiles,
        Tab::LargeFiles,
        Tab::Plan,
        Tab::Settings,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Scan => "Scan",
            Tab::Duplicates => "Duplicates",
            Tab::OldFiles => "Old Files",
            Tab::LargeFiles => "Large Files",
            Tab::Plan => "Plan",
            Tab::Settings => "Settings",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Tab::Scan => "◎",
            Tab::Duplicates => "⎘",
            Tab::OldFiles => "◴",
            Tab::LargeFiles => "▣",
            Tab::Plan => "✓",
            Tab::Settings => "⚙",
        }
    }
}

/// Result of a background scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub entries: Vec<FileEntry>,
    pub report: ScanReport,
}

/// Background scan state shared with the worker thread.
#[derive(Debug)]
pub struct ScanInFlight {
    pub started_path: PathBuf,
    pub result: Option<Result<ScanResult, String>>,
}

/// The main application state.
pub struct TidyApp {
    tab: Tab,

    // Inputs
    scan_path: String,
    scan_options: ScanOptions,

    // Environment
    env_report: EnvironmentReport,

    // Scan state
    scan_in_flight: Option<Arc<Mutex<ScanInFlight>>>,
    last_scan: Option<ScanResult>,

    // Analyzers' last results
    dedup_report: Option<DedupReport>,
    age_report: Option<AgeReport>,
    size_report: Option<SizeReport>,

    // Analyzer settings
    age_days: i64,
    size_top_n: usize,
    dedup_min_size: u64,

    // Classifier
    classifier: ImportanceClassifier,
    classifier_protected: Vec<String>,
    new_protected_input: String,

    // Plan
    plan: CleanupPlan,
    selected_action_kind: ActionKind,
    confirmation_input: String,

    // Safety gate: until the user explicitly unlocks the real
    // executor, every commit is a dry run.
    dry_run_locked: bool,

    // Status line
    status: String,
}

impl Default for TidyApp {
    fn default() -> Self {
        let default_path = std::env::var("HOME")
            .map(|h| format!("{}/Downloads", h))
            .unwrap_or_else(|_| "/tmp".to_string());
        Self {
            tab: Tab::Scan,
            scan_path: default_path,
            scan_options: ScanOptions::default(),
            env_report: environment::detect(),
            scan_in_flight: None,
            last_scan: None,
            dedup_report: None,
            age_report: None,
            size_report: None,
            age_days: 365,
            size_top_n: 50,
            dedup_min_size: 1024,
            classifier: ImportanceClassifier::new(),
            classifier_protected: Vec::new(),
            new_protected_input: String::new(),
            plan: CleanupPlan::new("interactive session"),
            selected_action_kind: ActionKind::Review,
            confirmation_input: String::new(),
            dry_run_locked: true,
            status: "Ready. No files will be deleted without your explicit confirmation.".into(),
        }
    }
}

impl TidyApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::gui::theme::apply(&cc.egui_ctx);
        Self::default()
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        let path = PathBuf::from(self.scan_path.trim());
        if !path.exists() {
            self.status = format!("Path does not exist: {}", path.display());
            return;
        }
        let options = self.scan_options.clone();
        let shared = Arc::new(Mutex::new(ScanInFlight {
            started_path: path.clone(),
            result: None,
        }));
        let shared_clone = shared.clone();
        let ctx_clone = ctx.clone();
        self.scan_in_flight = Some(shared);
        self.status = format!("Scanning {}…", path.display());
        thread::spawn(move || {
            let mut scanner = Scanner::new(options);
            let outcome = scanner.scan(&path).map_err(|e| e.to_string()).map(|_| {
                let report = scanner.report().clone();
                let entries = scanner.into_entries();
                ScanResult { entries, report }
            });
            if let Ok(mut s) = shared_clone.lock() {
                s.result = Some(outcome);
            }
            ctx_clone.request_repaint();
        });
    }

    fn poll_scan(&mut self) {
        let Some(shared) = self.scan_in_flight.clone() else { return };
        let Ok(mut guard) = shared.lock() else { return };
        if let Some(result) = guard.result.take() {
            drop(guard);
            self.scan_in_flight = None;
            match result {
                Ok(scan) => {
                    self.status = format!(
                        "Scanned {} files ({}) in {} directories",
                        scan.report.files_scanned,
                        format_bytes(scan.report.total_bytes),
                        scan.report.dirs_scanned,
                    );
                    self.last_scan = Some(scan);
                    // Invalidate downstream reports.
                    self.dedup_report = None;
                    self.age_report = None;
                    self.size_report = None;
                }
                Err(e) => {
                    self.status = format!("Scan failed: {}", e);
                }
            }
        }
    }

    fn run_dedup(&mut self) {
        let Some(scan) = &self.last_scan else {
            self.status = "Run a scan first.".into();
            return;
        };
        let report = Deduplicator::new()
            .with_min_size(self.dedup_min_size)
            .find(&scan.entries);
        self.status = format!(
            "Found {} duplicate groups ({} reclaimable)",
            report.groups_found,
            format_bytes(report.total_wasted_bytes)
        );
        self.dedup_report = Some(report);
    }

    fn run_age(&mut self) {
        let Some(scan) = &self.last_scan else {
            self.status = "Run a scan first.".into();
            return;
        };
        let report = AgeAnalyzer::new(self.age_days).analyze(&scan.entries);
        self.status = format!(
            "Found {} files older than {} days ({})",
            report.matched,
            report.threshold_days,
            format_bytes(report.total_bytes)
        );
        self.age_report = Some(report);
    }

    fn run_size(&mut self) {
        let Some(scan) = &self.last_scan else {
            self.status = "Run a scan first.".into();
            return;
        };
        let report = SizeAnalyzer::new(self.size_top_n).analyze(&scan.entries);
        self.status = format!(
            "Top {} files = {:.1}% of scan ({})",
            report.files.len(),
            report.top_share() * 100.0,
            format_bytes(report.total_bytes_in_top)
        );
        self.size_report = Some(report);
    }

    fn add_dup_group_to_plan(&mut self, group: &DupGroup) {
        // Skip the first (keeper); add the rest as plan candidates.
        for path in group.paths.iter().skip(1) {
            let verdict = self.classifier.classify(path);
            if !verdict.importance.is_deletable() {
                continue;
            }
            let action = PlanAction::new(
                path.clone(),
                group.size,
                self.selected_action_kind,
                verdict,
            )
            .with_note(format!("duplicate of {}", group.paths[0].display()))
            .with_note(format!("digest {}", &group.digest[..16]));
            self.plan.add(action);
        }
        self.status = format!("Added {} items from duplicate group", group.paths.len() - 1);
    }

    fn add_age_to_plan(&mut self) {
        let Some(report) = self.age_report.clone() else { return };
        let mut added = 0;
        for file in &report.files {
            let verdict = self.classifier.classify(&file.path);
            if !verdict.importance.is_deletable() {
                continue;
            }
            let action = PlanAction::new(
                file.path.clone(),
                file.size,
                self.selected_action_kind,
                verdict,
            )
            .with_note(format!("{} days since last access", file.days_since_access));
            self.plan.add(action);
            added += 1;
        }
        self.status = format!("Added {} aged files to plan", added);
    }

    fn add_size_to_plan(&mut self) {
        let Some(report) = self.size_report.clone() else { return };
        let mut added = 0;
        for file in &report.files {
            let verdict = self.classifier.classify(&file.path);
            if !verdict.importance.is_deletable() {
                continue;
            }
            let action = PlanAction::new(
                file.path.clone(),
                file.size,
                self.selected_action_kind,
                verdict,
            )
            .with_note("top-N largest".to_string());
            self.plan.add(action);
            added += 1;
        }
        self.status = format!("Added {} large files to plan", added);
    }

    fn commit_plan(&mut self) {
        let confirmation = self.confirmation_input.trim().to_string();
        let mut exec = FsExecutor::dry();
        match self
            .plan
            .commit(&mut exec, &self.classifier, &confirmation)
        {
            Ok(results) => {
                let ok = results.iter().filter(|r| r.success).count();
                self.status = format!(
                    "DRY-RUN: {}/{} actions would succeed",
                    ok,
                    results.len()
                );
            }
            Err(e) => {
                self.status = format!("Commit refused: {}", e);
            }
        }
    }

    // --- rendering -------------------------------------------------------

    fn header(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("PlausiDen Tidy")
                    .color(Palette::TEXT)
                    .size(22.0)
                    .strong(),
            );
            ui.label(
                RichText::new("smart cleaner — civil-rights edition")
                    .color(Palette::TEXT_DIM)
                    .italics(),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("env: {}", self.env_report.virtualization.label()))
                        .color(Palette::TEXT_DIM),
                );
            });
        });
        ui.separator();
    }

    fn env_banner(&self, ui: &mut Ui) {
        if let Some(banner) = self.env_report.warning_banner() {
            egui::Frame::none()
                .fill(Palette::WARN_BG)
                .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                .rounding(egui::Rounding::same(6.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("⚠  {}", banner))
                            .color(Palette::HIGH)
                            .strong(),
                    );
                    for note in &self.env_report.notes {
                        ui.label(RichText::new(format!("  • {}", note)).color(Palette::TEXT_DIM));
                    }
                });
            ui.add_space(6.0);
        }
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        ui.add_space(4.0);
        for tab in Tab::ALL {
            let selected = self.tab == tab;
            let label = RichText::new(format!("  {}  {}", tab.icon(), tab.label()))
                .color(if selected { Palette::ACCENT } else { Palette::TEXT })
                .size(16.0);
            let btn = ui.add_sized([170.0, 36.0], egui::SelectableLabel::new(selected, label));
            if btn.clicked() {
                self.tab = tab;
            }
        }

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);

        ui.label(RichText::new("Plan summary").color(Palette::TEXT_DIM).small());
        ui.label(format!("  items: {}", self.plan.len()));
        ui.label(format!(
            "  approved: {} ({})",
            self.plan.approved_count(),
            format_bytes(self.plan.total_bytes_approved())
        ));

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(RichText::new("Safety").color(Palette::TEXT_DIM).small());
        let lock_label = if self.dry_run_locked {
            RichText::new("🔒 dry-run locked ON").color(Palette::OK)
        } else {
            RichText::new("⚠ dry-run lock released").color(Palette::CRITICAL)
        };
        ui.label(lock_label);
    }

    fn scan_view(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        ui.heading("Scan");
        ui.label(
            RichText::new(
                "Walks a directory and records per-file metadata only. File contents are never read.",
            )
            .color(Palette::TEXT_DIM),
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Path:");
            ui.add(
                TextEdit::singleline(&mut self.scan_path)
                    .hint_text("/home/user/Downloads")
                    .desired_width(420.0),
            );
            let running = self.scan_in_flight.is_some();
            if ui
                .add_enabled(!running, egui::Button::new("Start scan"))
                .clicked()
            {
                self.start_scan(ctx);
            }
            if running {
                ui.spinner();
                ui.label(RichText::new("scanning…").color(Palette::TEXT_DIM));
            }
        });

        ui.add_space(6.0);
        ui.collapsing("Scan options", |ui| {
            ui.checkbox(&mut self.scan_options.include_hidden, "Include hidden files");
            ui.checkbox(&mut self.scan_options.follow_symlinks, "Follow symlinks");
            ui.checkbox(&mut self.scan_options.skip_mounts, "Stay on one filesystem");
            ui.horizontal(|ui| {
                ui.label("Minimum file size:");
                let mut v = self.scan_options.min_size as i64;
                if ui.add(egui::DragValue::new(&mut v).suffix(" bytes").speed(16.0)).changed() {
                    self.scan_options.min_size = v.max(0) as u64;
                }
            });
            let mut max_depth = self.scan_options.max_depth.unwrap_or(0) as i64;
            if ui
                .add(
                    egui::DragValue::new(&mut max_depth)
                        .speed(1.0)
                        .prefix("Max depth: ")
                        .range(0..=64),
                )
                .changed()
            {
                self.scan_options.max_depth = if max_depth == 0 { None } else { Some(max_depth as usize) };
            }
        });

        ui.add_space(10.0);
        ui.separator();

        if let Some(scan) = &self.last_scan {
            ui.label(
                RichText::new(format!(
                    "Last scan: {} files • {} • {} directories • {} I/O errors",
                    scan.report.files_scanned,
                    format_bytes(scan.report.total_bytes),
                    scan.report.dirs_scanned,
                    scan.report.io_errors
                ))
                .color(Palette::TEXT),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!(
                    "Skipped: {} hidden, {} symlinks",
                    scan.report.skipped_hidden, scan.report.skipped_symlink
                ))
                .color(Palette::TEXT_DIM),
            );

            ui.add_space(10.0);
            ui.label(RichText::new("Preview (first 200 entries)").color(Palette::TEXT_DIM));
            ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                for entry in scan.entries.iter().take(200) {
                    let verdict = self.classifier.classify(&entry.path);
                    ui.horizontal(|ui| {
                        importance_badge(ui, verdict.importance);
                        ui.label(
                            RichText::new(format_bytes(entry.size)).color(Palette::TEXT_DIM),
                        );
                        ui.label(entry.path.to_string_lossy().into_owned());
                    });
                }
            });
        } else {
            ui.label(RichText::new("No scan yet. Pick a path and hit 'Start scan'.").color(Palette::TEXT_DIM));
        }
    }

    fn dedup_view(&mut self, ui: &mut Ui) {
        ui.heading("Duplicate files");
        ui.label(
            RichText::new(
                "Two-stage detection: group by size, then BLAKE3-hash candidates. Hashes are computed locally and never leave the device.",
            )
            .color(Palette::TEXT_DIM),
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Minimum size:");
            let mut v = self.dedup_min_size as i64;
            if ui.add(egui::DragValue::new(&mut v).suffix(" bytes").speed(64.0)).changed() {
                self.dedup_min_size = v.max(1) as u64;
            }
            if ui.button("Find duplicates").clicked() {
                self.run_dedup();
            }
        });

        ui.add_space(8.0);
        ui.separator();

        if let Some(report) = self.dedup_report.clone() {
            ui.label(
                RichText::new(format!(
                    "{} groups, {} files, {} reclaimable",
                    report.groups_found,
                    report.files_in_groups,
                    format_bytes(report.total_wasted_bytes)
                ))
                .color(Palette::TEXT),
            );
            ui.add_space(6.0);
            ScrollArea::vertical().max_height(460.0).show(ui, |ui| {
                for (i, group) in report.groups.iter().enumerate() {
                    let header = format!(
                        "Group {} — {} copies • {} each • {} reclaimable",
                        i + 1,
                        group.paths.len(),
                        format_bytes(group.size),
                        format_bytes(group.wasted_bytes())
                    );
                    egui::CollapsingHeader::new(
                        RichText::new(header).color(Palette::TEXT),
                    )
                    .default_open(false)
                    .show(ui, |ui| {
                        for (idx, p) in group.paths.iter().enumerate() {
                            ui.horizontal(|ui| {
                                if idx == 0 {
                                    ui.label(
                                        RichText::new("KEEP")
                                            .color(Palette::OK)
                                            .monospace(),
                                    );
                                } else {
                                    ui.label(
                                        RichText::new("DUP ")
                                            .color(Palette::TEXT_DIM)
                                            .monospace(),
                                    );
                                }
                                ui.label(p.to_string_lossy().into_owned());
                            });
                        }
                        ui.add_space(4.0);
                        let add = ui.button("Add extras to plan");
                        if add.clicked() {
                            self.add_dup_group_to_plan(group);
                        }
                    });
                }
            });
        } else if self.last_scan.is_some() {
            ui.label(RichText::new("Click 'Find duplicates' to analyze the last scan.").color(Palette::TEXT_DIM));
        } else {
            ui.label(RichText::new("Scan a directory first.").color(Palette::TEXT_DIM));
        }
    }

    fn age_view(&mut self, ui: &mut Ui) {
        ui.heading("Old files");
        ui.label(
            RichText::new(
                "Flags files untouched for longer than the threshold. Uses the more recent of atime and mtime.",
            )
            .color(Palette::TEXT_DIM),
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Days since access:");
            ui.add(egui::Slider::new(&mut self.age_days, 30..=3650));
            if ui.button("Analyze").clicked() {
                self.run_age();
            }
        });

        ui.add_space(8.0);
        ui.separator();

        if let Some(report) = self.age_report.clone() {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{} matched • {}",
                        report.matched,
                        format_bytes(report.total_bytes)
                    ))
                    .color(Palette::TEXT),
                );
                if ui.button("Add all deletable to plan").clicked() {
                    self.add_age_to_plan();
                }
            });

            ui.add_space(6.0);
            ScrollArea::vertical().max_height(460.0).show(ui, |ui| {
                for file in report.files.iter().take(500) {
                    let verdict = self.classifier.classify(&file.path);
                    ui.horizontal(|ui| {
                        importance_badge(ui, verdict.importance);
                        ui.label(
                            RichText::new(format!("{:>5} d", file.days_since_access))
                                .color(Palette::TEXT_DIM),
                        );
                        ui.label(
                            RichText::new(format_bytes(file.size)).color(Palette::TEXT_DIM),
                        );
                        ui.label(file.path.to_string_lossy().into_owned());
                    });
                }
            });
        } else {
            ui.label(RichText::new("No analysis yet.").color(Palette::TEXT_DIM));
        }
    }

    fn size_view(&mut self, ui: &mut Ui) {
        ui.heading("Large files");
        ui.label(
            RichText::new("Top-N largest files by bytes on disk.")
                .color(Palette::TEXT_DIM),
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Top:");
            ui.add(egui::Slider::new(&mut self.size_top_n, 5..=500));
            if ui.button("Analyze").clicked() {
                self.run_size();
            }
        });

        ui.add_space(8.0);
        ui.separator();

        if let Some(report) = self.size_report.clone() {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{} files • {} ({:.1}% of scan)",
                        report.files.len(),
                        format_bytes(report.total_bytes_in_top),
                        report.top_share() * 100.0
                    ))
                    .color(Palette::TEXT),
                );
                if ui.button("Add all deletable to plan").clicked() {
                    self.add_size_to_plan();
                }
            });

            ui.add_space(6.0);
            ScrollArea::vertical().max_height(460.0).show(ui, |ui| {
                let max_size = report.files.first().map(|f| f.size).unwrap_or(1) as f32;
                for file in &report.files {
                    let verdict = self.classifier.classify(&file.path);
                    ui.horizontal(|ui| {
                        importance_badge(ui, verdict.importance);
                        ui.label(
                            RichText::new(format_bytes(file.size))
                                .color(Palette::TEXT)
                                .monospace(),
                        );
                        // Inline bar
                        let width = (file.size as f32 / max_size) * 120.0;
                        let (rect, _) = ui.allocate_exact_size(
                            egui::vec2(width.max(2.0), 8.0),
                            egui::Sense::hover(),
                        );
                        ui.painter().rect_filled(
                            rect,
                            egui::Rounding::same(2.0),
                            importance_color(verdict.importance),
                        );
                        ui.label(file.path.to_string_lossy().into_owned());
                    });
                }
            });
        } else {
            ui.label(RichText::new("No analysis yet.").color(Palette::TEXT_DIM));
        }
    }

    fn plan_view(&mut self, ui: &mut Ui) {
        ui.heading("Cleanup plan");
        ui.label(
            RichText::new(
                "Review every item. Nothing runs until you type the confirmation token and press Commit. Commit is dry-run until you explicitly release the safety lock.",
            )
            .color(Palette::TEXT_DIM),
        );
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label("Default action for new items:");
            egui::ComboBox::from_id_salt("action_kind")
                .selected_text(self.selected_action_kind.description())
                .show_ui(ui, |ui| {
                    for kind in [
                        ActionKind::Review,
                        ActionKind::MoveToTrash,
                        ActionKind::SimpleDelete,
                        ActionKind::SecurePurge,
                    ] {
                        ui.selectable_value(
                            &mut self.selected_action_kind,
                            kind,
                            kind.description(),
                        );
                    }
                });

            if ui.button("Approve all").clicked() {
                self.plan.approve_all();
            }
            if ui.button("Unapprove all").clicked() {
                self.plan.unapprove_all();
            }
            if ui.button("Clear plan").clicked() {
                self.plan = CleanupPlan::new("interactive session");
                self.confirmation_input.clear();
            }
        });

        ui.add_space(8.0);

        ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
            let mut to_remove: Option<usize> = None;
            let mut approvals: Vec<(usize, bool)> = Vec::new();
            for (i, action) in self.plan.actions.iter().enumerate() {
                ui.horizontal(|ui| {
                    let mut approved = action.approved;
                    if ui.checkbox(&mut approved, "").changed() {
                        approvals.push((i, approved));
                    }
                    importance_badge(ui, action.verdict.importance);
                    ui.label(
                        RichText::new(action.kind.description())
                            .color(if action.kind.is_destructive() {
                                Palette::HIGH
                            } else {
                                Palette::ACCENT
                            })
                            .monospace(),
                    );
                    ui.label(
                        RichText::new(format_bytes(action.size)).color(Palette::TEXT_DIM),
                    );
                    ui.label(action.path.to_string_lossy().into_owned());
                    if ui.small_button("✕").clicked() {
                        to_remove = Some(i);
                    }
                });
                if !action.notes.is_empty() {
                    ui.indent("notes", |ui| {
                        for note in &action.notes {
                            ui.label(
                                RichText::new(format!("• {}", note))
                                    .color(Palette::TEXT_DIM)
                                    .small(),
                            );
                        }
                    });
                }
            }
            for (idx, approved) in approvals {
                if approved {
                    self.plan.approve_index(idx);
                } else {
                    self.plan.unapprove_index(idx);
                }
            }
            if let Some(i) = to_remove {
                self.plan.remove_at(i);
            }
        });

        ui.add_space(10.0);
        ui.separator();

        let digest = self.plan.confirmation_digest();
        ui.label(
            RichText::new(format!(
                "Confirmation token: {}   ({} approved · {} to reclaim)",
                digest,
                self.plan.approved_count(),
                format_bytes(self.plan.total_bytes_approved()),
            ))
            .color(Palette::TEXT),
        );
        ui.horizontal(|ui| {
            ui.label("Type the token:");
            ui.add(TextEdit::singleline(&mut self.confirmation_input).desired_width(180.0));
            let token_matches = self.confirmation_input.trim() == digest;
            let commit_label = if self.dry_run_locked {
                "Commit (dry-run)"
            } else {
                "Commit (LIVE)"
            };
            let commit_color = if self.dry_run_locked {
                Palette::ACCENT
            } else {
                Palette::CRITICAL
            };
            if ui
                .add_enabled(
                    token_matches && self.plan.approved_count() > 0,
                    egui::Button::new(RichText::new(commit_label).color(commit_color)),
                )
                .clicked()
            {
                self.commit_plan();
            }
        });
    }

    fn settings_view(&mut self, ui: &mut Ui) {
        ui.heading("Settings");
        ui.label(
            RichText::new(
                "Adjust the importance classifier. Protected paths are refused even if a plan approves them.",
            )
            .color(Palette::TEXT_DIM),
        );
        ui.add_space(10.0);

        ui.label(RichText::new("Protected paths").color(Palette::TEXT).strong());
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.new_protected_input)
                    .hint_text("/home/user/secret")
                    .desired_width(320.0),
            );
            if ui.button("Add").clicked() && !self.new_protected_input.trim().is_empty() {
                let path = self.new_protected_input.trim().to_string();
                self.classifier.protect(PathBuf::from(&path));
                self.classifier_protected.push(path);
                self.new_protected_input.clear();
            }
        });
        let mut remove: Option<usize> = None;
        for (i, p) in self.classifier_protected.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("  • {}", p)).color(Palette::TEXT_DIM),
                );
                if ui.small_button("remove").clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            self.classifier_protected.remove(i);
            // Rebuild classifier from scratch so the removal sticks.
            let mut c = ImportanceClassifier::new();
            for p in &self.classifier_protected {
                c.protect(PathBuf::from(p));
            }
            self.classifier = c;
        }

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(10.0);

        ui.label(RichText::new("Safety lock").color(Palette::TEXT).strong());
        ui.label(
            RichText::new(
                "While the safety lock is on, every Commit is a dry run. Nothing on disk will change.",
            )
            .color(Palette::TEXT_DIM),
        );
        ui.checkbox(&mut self.dry_run_locked, "Dry-run lock");
        if !self.dry_run_locked {
            ui.label(
                RichText::new(
                    "⚠  Lock released. The current implementation still defaults the executor to dry-run; real deletion will be added in a later release only after end-to-end UI review.",
                )
                .color(Palette::CRITICAL),
            );
        }

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(10.0);

        ui.label(RichText::new("Environment").color(Palette::TEXT).strong());
        ui.label(format!(
            "Virtualization: {}",
            self.env_report.virtualization.label()
        ));
        ui.label(format!(
            "Storage class: {}",
            self.env_report.storage_class.label()
        ));
        ui.label(format!(
            "Overwrite effective: {}",
            if self.env_report.overwrite_effective {
                "yes"
            } else {
                "no (crypto-shred recommended)"
            }
        ));
        for note in &self.env_report.notes {
            ui.label(RichText::new(format!("• {}", note)).color(Palette::TEXT_DIM));
        }
    }

    fn status_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(&self.status).color(Palette::TEXT_DIM));
        });
    }
}

fn importance_badge(ui: &mut Ui, imp: Importance) {
    let color = importance_color(imp);
    let label = importance_label(imp);
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(70.0, 18.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, egui::Rounding::same(4.0), color);
    let text_color = if matches!(imp, Importance::Critical | Importance::High) {
        Color32::WHITE
    } else {
        Color32::BLACK
    };
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::monospace(10.0),
        text_color,
    );
}

impl eframe::App for TidyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            self.header(ui);
            self.env_banner(ui);
        });

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(200.0)
            .show(ctx, |ui| {
                self.sidebar(ui);
            });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            self.status_bar(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Scan => self.scan_view(ui, ctx),
            Tab::Duplicates => self.dedup_view(ui),
            Tab::OldFiles => self.age_view(ui),
            Tab::LargeFiles => self.size_view(ui),
            Tab::Plan => self.plan_view(ui),
            Tab::Settings => self.settings_view(ui),
        });

        // Keep the UI responsive while a scan is running.
        if self.scan_in_flight.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}
