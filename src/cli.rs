use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::append::append_to_archive;
use crate::archiveio::{
    assert_archive_output_path_clear, canonical_archive_base_path, discover_archive_segment_paths,
    is_multipart_segment_path, parent_dir_or_dot,
};
use crate::constants::{CODEC_DEFLATE, FLAG_ENCRYPTED};
use crate::ecc::repair_archive;
use crate::repair::repair_archive_with_progress;
use crate::error::{AmberError, AmberResult};
use crate::harden::append_amcf_parity;
use crate::inputscan::scan_inputs;
use crate::reader::ArchiveReader;
use crate::rebuild::rebuild_archive;
use crate::writer::ArchiveWriter;
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealOptions {
    pub output: Option<PathBuf>,
    pub password: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub compress: bool,
    pub part_size: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealSummary {
    pub output_path: PathBuf,
    pub file_count: usize,
    pub dir_count: usize,
    pub symlink_count: usize,
    pub processed_bytes: u64,
    pub multipart: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SealProgress {
    SealingInput(PathBuf),
    SealingFile {
        archive_path: String,
        processed_bytes: u64,
        total_bytes: u64,
    },
    Finalizing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListEntry {
    pub kind: u64,
    pub path: String,
    pub size: u64,
    pub symlink_target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListSummary {
    pub entries: Vec<ListEntry>,
    pub anchor_total_count: usize,
    pub anchor_fail_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifySummary {
    pub ok: bool,
    pub anchor_total_count: usize,
    pub anchor_fail_count: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExistsMode {
    Overwrite,
    Skip,
    Rename,
    Fail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsealOptions {
    pub outdir: PathBuf,
    pub password: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub paths: Vec<String>,
    pub exists: ExistsMode,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnsealSummary {
    pub extracted_files: usize,
    pub total_files: usize,
    pub processed_bytes: u64,
    pub created_dirs: usize,
    pub created_symlinks: usize,
    pub total_symlinks: usize,
    pub skipped_entries: usize,
    pub renamed_entries: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnsealProgress {
    StartArchive(PathBuf),
    CreatingDir {
        archive_path: String,
    },
    Symlinking {
        archive_path: String,
        target: String,
    },
    SkippingExisting {
        archive_path: String,
    },
    RenamedTo {
        path: PathBuf,
    },
    UnsealingFile {
        archive_path: String,
        processed_files: usize,
        total_files: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveInfo {
    pub path: PathBuf,
    pub version_major: u16,
    pub version_minor: u16,
    pub uuid_hex: String,
    pub created_sec: u64,
    pub flags: u32,
    pub encrypted: bool,
    pub default_chunk_size: Option<u64>,
    pub default_codec: Option<u64>,
    pub multipart_part_size: Option<u64>,
    pub segment_count: usize,
    pub entry_count: usize,
    pub file_count: usize,
    pub dir_count: usize,
    pub symlink_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScrubOptions {
    pub recursive: bool,
    pub jobs: usize,
    pub password: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub repair: bool,
    pub safe: bool,
    pub harden_extra: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScrubResult {
    pub path: String,
    pub status: String,
    pub global_fixed: usize,
    pub harden_added: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScrubSummary {
    pub results: Vec<ScrubResult>,
    pub ok: usize,
    pub repaired: usize,
    pub skipped: usize,
    pub failed: usize,
}

pub fn parse_part_size(value: &str) -> Result<u64, String> {
    let text = value.trim();
    if text.is_empty() {
        return Err("part size must not be empty".into());
    }
    let suffixes = [
        ("kib", 1024u64),
        ("kb", 1024u64),
        ("k", 1024u64),
        ("mib", 1024u64 * 1024),
        ("mb", 1024u64 * 1024),
        ("m", 1024u64 * 1024),
        ("gib", 1024u64 * 1024 * 1024),
        ("gb", 1024u64 * 1024 * 1024),
        ("g", 1024u64 * 1024 * 1024),
        ("tib", 1024u64 * 1024 * 1024 * 1024),
        ("tb", 1024u64 * 1024 * 1024 * 1024),
        ("t", 1024u64 * 1024 * 1024 * 1024),
    ];
    let lower = text.to_ascii_lowercase();
    for (suffix, scale) in suffixes {
        if let Some(number) = lower.strip_suffix(suffix) {
            let number = number.trim();
            if number.is_empty() {
                return Err("missing numeric part in part size".into());
            }
            let base = number
                .parse::<u64>()
                .map_err(|_| "invalid part size".to_string())?;
            return base
                .checked_mul(scale)
                .ok_or_else(|| "part size is too large".to_string());
        }
    }
    text.parse::<u64>()
        .map_err(|_| "invalid part size".to_string())
}

pub fn seal_archive(
    inputs: &[impl AsRef<Path>],
    options: &SealOptions,
) -> AmberResult<SealSummary> {
    seal_archive_with_progress(inputs, options, |_| {})
}

pub fn seal_archive_with_progress(
    inputs: &[impl AsRef<Path>],
    options: &SealOptions,
    mut progress: impl FnMut(SealProgress),
) -> AmberResult<SealSummary> {
    if inputs.is_empty() {
        return Err(AmberError::Invalid("No input paths provided".into()));
    }
    for input in inputs {
        progress(SealProgress::SealingInput(input.as_ref().to_path_buf()));
    }
    let output_path = match options.output.as_ref() {
        Some(path) => path.clone(),
        None if inputs.len() == 1 => {
            PathBuf::from(format!("{}.amber", inputs[0].as_ref().display()))
        }
        None => {
            return Err(AmberError::Invalid(
                "Output path required when sealing multiple inputs".into(),
            ));
        }
    };
    let output_fs_path = absolutize_operational_path(&output_path)?;
    let multipart = options.part_size.is_some();
    assert_archive_output_path_clear(&output_fs_path, multipart)?;

    let scanned = scan_inputs(inputs)?;
    let total_bytes = scanned
        .files
        .iter()
        .map(|file| file.size)
        .sum::<u64>()
        .max(1);
    let mut processed_bytes = 0u64;
    let seal_result = (|| -> AmberResult<SealSummary> {
        let mut writer = ArchiveWriter::new(
            &output_fs_path,
            None,
            if options.compress {
                Some(CODEC_DEFLATE)
            } else {
                None
            },
            options.password.as_deref(),
            options.keyfile.as_deref(),
            options.part_size,
            None,
            None,
            None,
            None,
        )?;
        writer.open()?;
        for dir in &scanned.dirs {
            writer.add_dir(
                &dir.archive_path,
                dir.metadata.mode,
                dir.metadata.mtime_sec,
                dir.metadata.mtime_nsec,
                dir.metadata.atime_sec,
                dir.metadata.atime_nsec,
            )?;
        }
        for symlink in &scanned.symlinks {
            writer.add_symlink(&symlink.archive_path, &symlink.target)?;
        }
        for file in &scanned.files {
            writer.add_file(
                &file.archive_path,
                &file.fs_path,
                None,
                None,
                file.metadata.mode,
            )?;
            processed_bytes = processed_bytes.saturating_add(file.size);
            progress(SealProgress::SealingFile {
                archive_path: file.archive_path.clone(),
                processed_bytes,
                total_bytes,
            });
        }
        progress(SealProgress::Finalizing);
        writer.finalize()?;
        writer.close();

        Ok(SealSummary {
            output_path,
            file_count: scanned.files.len(),
            dir_count: scanned.dirs.len(),
            symlink_count: scanned.symlinks.len(),
            processed_bytes,
            multipart,
        })
    })();

    if seal_result.is_err() {
        cleanup_failed_fresh_archive_write(&output_fs_path, multipart)?;
    }

    seal_result
}

fn absolutize_operational_path(path: &Path) -> AmberResult<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn cleanup_failed_fresh_archive_write(base_path: &Path, multipart: bool) -> AmberResult<()> {
    if multipart {
        let segment_paths = match discover_archive_segment_paths(base_path) {
            Ok(paths) => paths,
            Err(AmberError::NotFound(_)) => Vec::new(),
            Err(err) => return Err(err),
        };
        for segment_path in segment_paths {
            match fs::remove_file(&segment_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
    } else {
        match fs::remove_file(base_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

pub fn list_archive(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<ListSummary> {
    let mut reader = ArchiveReader::new_with_credentials(
        archive.as_ref(),
        password.map(str::to_owned),
        keyfile.map(Path::to_path_buf),
    );
    reader.open()?;
    Ok(ListSummary {
        entries: reader
            .list()
            .iter()
            .map(|entry| ListEntry {
                kind: entry.kind,
                path: entry.path.clone(),
                size: entry.size,
                symlink_target: entry.symlink_target.clone(),
            })
            .collect(),
        anchor_total_count: reader.anchor_total_count,
        anchor_fail_count: reader.anchor_fail_count,
    })
}

pub fn verify_archive(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<VerifySummary> {
    let mut reader = ArchiveReader::new_with_credentials(
        archive.as_ref(),
        password.map(str::to_owned),
        keyfile.map(Path::to_path_buf),
    );
    reader.open()?;
    let ok = reader.verify()?;
    Ok(VerifySummary {
        ok,
        anchor_total_count: reader.anchor_total_count,
        anchor_fail_count: reader.anchor_fail_count,
    })
}

pub fn archive_info(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<ArchiveInfo> {
    let mut reader = ArchiveReader::new_with_credentials(
        archive.as_ref(),
        password.map(str::to_owned),
        keyfile.map(Path::to_path_buf),
    );
    reader.open()?;
    let superblock = reader
        .superblock
        .as_ref()
        .ok_or_else(|| AmberError::Invalid("missing superblock".into()))?;
    Ok(ArchiveInfo {
        path: archive.as_ref().to_path_buf(),
        version_major: superblock.version_major,
        version_minor: superblock.version_minor,
        uuid_hex: hex_lower(&superblock.uuid),
        created_sec: superblock.created_sec,
        flags: superblock.flags,
        encrypted: (superblock.flags & FLAG_ENCRYPTED) != 0,
        default_chunk_size: reader
            .index
            .as_ref()
            .and_then(|idx| crate::tlv::get_u64(idx, "default_chunk_size")),
        default_codec: reader
            .index
            .as_ref()
            .and_then(|idx| crate::tlv::get_u64(idx, "default_codec")),
        multipart_part_size: (superblock.multipart_part_size != 0)
            .then_some(superblock.multipart_part_size),
        segment_count: reader.segments_meta.len(),
        entry_count: reader.entries.len(),
        file_count: reader
            .entries
            .iter()
            .filter(|entry| entry.kind == 0)
            .count(),
        dir_count: reader
            .entries
            .iter()
            .filter(|entry| entry.kind == 1)
            .count(),
        symlink_count: reader
            .entries
            .iter()
            .filter(|entry| entry.kind == 2)
            .count(),
    })
}

pub fn unseal_archive(
    archive: impl AsRef<Path>,
    options: &UnsealOptions,
) -> AmberResult<UnsealSummary> {
    unseal_archive_with_progress(archive, options, |_| {})
}

pub fn unseal_archive_with_progress(
    archive: impl AsRef<Path>,
    options: &UnsealOptions,
    mut progress: impl FnMut(UnsealProgress),
) -> AmberResult<UnsealSummary> {
    progress(UnsealProgress::StartArchive(archive.as_ref().to_path_buf()));
    let mut reader = ArchiveReader::new_with_credentials(
        archive.as_ref(),
        options.password.clone(),
        options.keyfile.clone(),
    );
    reader.open()?;
    let wanted = options
        .paths
        .iter()
        .map(|path| crate::pathutil::validate_archive_path(path))
        .collect::<AmberResult<Vec<_>>>()?;
    let mut entries = reader.list().to_vec();
    if !wanted.is_empty() {
        entries.retain(|entry| {
            wanted
                .iter()
                .any(|path| entry.path == *path || entry.path.starts_with(&format!("{path}/")))
        });
    }

    let base_outdir = fs::canonicalize(&options.outdir).or_else(|_| {
        fs::create_dir_all(&options.outdir)?;
        fs::canonicalize(&options.outdir)
    })?;
    let mut summary = UnsealSummary {
        total_files: entries.iter().filter(|entry| entry.kind == 0).count(),
        total_symlinks: entries.iter().filter(|entry| entry.kind == 2).count(),
        ..UnsealSummary::default()
    };

    for entry in entries {
        let dst = safe_destination(&base_outdir, &entry.path)?;
        match entry.kind {
            1 => {
                prepare_parent(&base_outdir, &dst)?;
                fs::create_dir_all(&dst)?;
                assert_within_outdir(&base_outdir, &dst)?;
                progress(UnsealProgress::CreatingDir {
                    archive_path: entry.path.clone(),
                });
                apply_extracted_metadata(
                    &dst,
                    entry.mode,
                    entry.atime_sec,
                    entry.atime_nsec,
                    entry.mtime_sec,
                    entry.mtime_nsec,
                )?;
                summary.created_dirs += 1;
            }
            2 => {
                let target = entry.symlink_target.as_deref().ok_or_else(|| {
                    AmberError::Invalid(format!("symlink entry is missing target: {}", entry.path))
                })?;
                let actual_dst = resolve_existing_destination(
                    &base_outdir,
                    &dst,
                    options.exists,
                    &mut summary,
                    true,
                )?;
                let Some(actual_dst) = actual_dst else {
                    progress(UnsealProgress::SkippingExisting {
                        archive_path: entry.path.clone(),
                    });
                    continue;
                };
                prepare_parent(&base_outdir, &actual_dst)?;
                validate_symlink_destination(&base_outdir, &actual_dst, target)?;
                create_symlink(target, &actual_dst)?;
                assert_within_outdir(&base_outdir, &actual_dst)?;
                progress(UnsealProgress::Symlinking {
                    archive_path: entry.path.clone(),
                    target: target.to_owned(),
                });
                if actual_dst != dst {
                    progress(UnsealProgress::RenamedTo { path: actual_dst.clone() });
                }
                summary.created_symlinks += 1;
            }
            0 => {
                let actual_dst = resolve_existing_destination(
                    &base_outdir,
                    &dst,
                    options.exists,
                    &mut summary,
                    false,
                )?;
                let Some(actual_dst) = actual_dst else {
                    progress(UnsealProgress::SkippingExisting {
                        archive_path: entry.path.clone(),
                    });
                    continue;
                };
                prepare_parent(&base_outdir, &actual_dst)?;
                progress(UnsealProgress::UnsealingFile {
                    archive_path: entry.path.clone(),
                    processed_files: summary.extracted_files + 1,
                    total_files: summary.total_files,
                });
                reader.extract(&entry, &actual_dst)?;
                assert_within_outdir(&base_outdir, &actual_dst)?;
                apply_extracted_metadata(
                    &actual_dst,
                    entry.mode,
                    entry.atime_sec,
                    entry.atime_nsec,
                    entry.mtime_sec,
                    entry.mtime_nsec,
                )?;
                if actual_dst != dst {
                    progress(UnsealProgress::RenamedTo { path: actual_dst.clone() });
                }
                summary.processed_bytes = summary.processed_bytes.saturating_add(entry.size);
                summary.extracted_files += 1;
            }
            _ => {}
        }
    }

    Ok(summary)
}

pub fn append_command(
    archive: impl AsRef<Path>,
    inputs: &[impl AsRef<Path>],
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<()> {
    let verify = verify_archive(&archive, password, keyfile)?;
    if !verify.ok {
        return Err(AmberError::Invalid(
            "Verification failed; run amber repair before appending.".into(),
        ));
    }
    append_to_archive(archive, inputs, password, keyfile)
}

pub fn rebuild_command(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<PathBuf> {
    rebuild_archive(archive, password, keyfile, ".bak")
}

pub fn harden_command(
    archive: impl AsRef<Path>,
    extra_ppm: usize,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<usize> {
    assert_archive_clean_for_harden(&archive, password, keyfile)?;
    append_amcf_parity(archive, extra_ppm, password, keyfile)
}

pub fn assert_archive_clean_for_harden(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<()> {
    let verify = verify_archive(&archive, password, keyfile)?;
    if !verify.ok {
        return Err(AmberError::Invalid(
            "Verification failed before harden".into(),
        ));
    }
    Ok(())
}

pub fn repair_command(
    archive: impl AsRef<Path>,
    safe: bool,
    password: Option<&str>,
    keyfile: Option<&Path>,
    output: Option<&Path>,
) -> AmberResult<crate::repair::ECCRepairResult> {
    repair_command_with_progress(archive, safe, password, keyfile, output, None)
}

pub fn repair_command_with_progress(
    archive: impl AsRef<Path>,
    safe: bool,
    password: Option<&str>,
    keyfile: Option<&Path>,
    output: Option<&Path>,
    progress: Option<&mut dyn FnMut(String)>,
) -> AmberResult<crate::repair::ECCRepairResult> {
    let final_output = match output {
        Some(path) => Some(path.to_path_buf()),
        None if safe => Some(default_repaired_output_path(archive.as_ref())?),
        None => None,
    };
    repair_archive_with_progress(archive, password, keyfile, final_output.as_deref(), progress)
}

pub fn scrub_archives(
    paths: &[impl AsRef<Path>],
    options: &ScrubOptions,
) -> AmberResult<ScrubSummary> {
    let archive_paths = iter_archives(paths, options.recursive)?;
    if archive_paths.is_empty() {
        return Err(AmberError::Invalid("No archives found".into()));
    }

    let jobs = options.jobs.max(1);
    let results = if jobs == 1 || archive_paths.len() == 1 {
        archive_paths
            .iter()
            .map(|path| {
                scrub_one(
                    path,
                    options.password.as_deref(),
                    options.keyfile.as_deref(),
                    options.repair,
                    options.safe,
                    options.harden_extra,
                )
            })
            .collect::<Vec<_>>()
    } else {
        run_scrub_workers(archive_paths, jobs, options)
    };

    let ok = results
        .iter()
        .filter(|result| matches!(result.status.as_str(), "ok" | "repaired"))
        .count();
    let repaired = results
        .iter()
        .filter(|result| result.status == "repaired")
        .count();
    let skipped = results
        .iter()
        .filter(|result| result.status.starts_with("skip"))
        .count();
    let failed = results
        .iter()
        .filter(|result| {
            result.status == "fail"
                || result.status.starts_with("error")
                || result.status.starts_with("hint")
        })
        .count();

    Ok(ScrubSummary {
        results,
        ok,
        repaired,
        skipped,
        failed,
    })
}

pub fn format_scrub_summary(summary: &ScrubSummary, quiet: bool) -> String {
    let mut out = String::new();
    for result in &summary.results {
        if !quiet {
            out.push_str(&format!(
                "{:8} {} (global={} harden+={})\n",
                result.status.to_ascii_uppercase(),
                result.path,
                result.global_fixed,
                result.harden_added
            ));
        }
        if result.status.starts_with("hint")
            && let Some(message) = result.message.as_deref()
        {
            out.push_str("  ");
            out.push_str(message);
            out.push('\n');
        }
    }
    out.push_str(&format!(
        "Summary: ok={} repaired={} skipped={} failed={}",
        summary.ok, summary.repaired, summary.skipped, summary.failed
    ));
    out
}

pub fn scrub_summary_json(summary: &ScrubSummary) -> AmberResult<String> {
    serde_json::to_string(summary)
        .map_err(|err| AmberError::Invalid(format!("failed to serialize scrub summary: {err}")))
}

pub fn default_repaired_output_path(path: impl AsRef<Path>) -> AmberResult<PathBuf> {
    let path = path.as_ref();
    if is_multipart_archive(path) {
        return Ok(PathBuf::from(format!(
            "{}.repaired",
            canonical_archive_base_path(path)?.display()
        )));
    }
    let base = canonical_archive_base_path(path)?;
    let parent = parent_dir_or_dot(&base);
    let stem = base
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| AmberError::Invalid("archive path must be valid UTF-8".into()))?;
    let ext = base
        .extension()
        .and_then(|ext| ext.to_str())
        .ok_or_else(|| AmberError::Invalid("archive path must carry an extension".into()))?;
    Ok(parent.join(format!("{stem}.repaired.{ext}")))
}

pub fn archive_error_is_locked(path: impl AsRef<Path>, err: &AmberError) -> bool {
    is_locked_error(path.as_ref(), err)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn run_scrub_workers(
    archive_paths: Vec<PathBuf>,
    jobs: usize,
    options: &ScrubOptions,
) -> Vec<ScrubResult> {
    let task_count = archive_paths.len();
    let tasks = Arc::new(Mutex::new(
        archive_paths.into_iter().enumerate().collect::<Vec<_>>(),
    ));
    let results = Arc::new(Mutex::new(vec![None; task_count]));
    let worker_count = jobs.min(task_count);

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let tasks = Arc::clone(&tasks);
            let results = Arc::clone(&results);
            let password = options.password.clone();
            let keyfile = options.keyfile.clone();
            let repair = options.repair;
            let safe = options.safe;
            let harden_extra = options.harden_extra;
            scope.spawn(move || {
                loop {
                    let next = {
                        let mut locked = tasks.lock().expect("scrub task mutex poisoned");
                        locked.pop()
                    };
                    let Some((index, path)) = next else { break };
                    let result = scrub_one(
                        &path,
                        password.as_deref(),
                        keyfile.as_deref(),
                        repair,
                        safe,
                        harden_extra,
                    );
                    let mut locked = results.lock().expect("scrub result mutex poisoned");
                    locked[index] = Some(result);
                }
            });
        }
    });

    Arc::into_inner(results)
        .expect("scrub workers still hold result state")
        .into_inner()
        .expect("scrub result mutex poisoned")
        .into_iter()
        .map(|item| item.expect("scrub worker did not fill ordered result"))
        .collect()
}

fn iter_archives(paths: &[impl AsRef<Path>], recursive: bool) -> AmberResult<Vec<PathBuf>> {
    let mut found = Vec::new();
    for path in paths {
        let path = path.as_ref();
        if path.is_dir() {
            let mut seen_multipart_bases = Vec::new();
            scan_archive_dir(path, recursive, &mut seen_multipart_bases, &mut found)?;
            continue;
        }
        let lower = path.to_string_lossy().to_ascii_lowercase();
        if lower.ends_with(".amber") || is_multipart_archive(path) {
            found.push(path.to_path_buf());
        }
    }
    Ok(found)
}

fn scan_archive_dir(
    dir: &Path,
    recursive: bool,
    seen_multipart_bases: &mut Vec<PathBuf>,
    found: &mut Vec<PathBuf>,
) -> AmberResult<()> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                scan_archive_dir(&path, true, seen_multipart_bases, found)?;
            }
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.to_ascii_lowercase().ends_with(".amber") {
            found.push(path);
            continue;
        }
        if is_multipart_segment_path(&path) && name.ends_with(".001") {
            let base = canonical_archive_base_path(&path)?;
            if !seen_multipart_bases.iter().any(|seen| seen == &base) {
                seen_multipart_bases.push(base.clone());
                found.push(base);
            }
        }
    }
    Ok(())
}

fn is_multipart_archive(path: &Path) -> bool {
    discover_archive_segment_paths(path)
        .map(|segments| segments.len() > 1)
        .unwrap_or(false)
}

fn scrub_one(
    path: &Path,
    password: Option<&str>,
    keyfile: Option<&Path>,
    do_repair: bool,
    safe: bool,
    harden_ppm: usize,
) -> ScrubResult {
    let path_text = path.display().to_string();
    let mut result = ScrubResult {
        path: path_text,
        status: "unknown".into(),
        global_fixed: 0,
        harden_added: 0,
        message: None,
    };

    let ok = match verify_archive(path, password, keyfile) {
        Ok(summary) => summary.ok,
        Err(err) => {
            if err.is_rebuild_index_candidate() {
                result.status = "hint:repair".into();
                result.message = Some(
                    "Index appears inconsistent or corrupted. Run 'amber repair --safe' to rebuild the index and attempt recovery.".into(),
                );
            } else if is_locked_error(path, &err) {
                result.status = "skip:locked".into();
                result.message =
                    Some("encrypted archive skipped (missing/incorrect credentials)".into());
            } else {
                result.status = "fail".into();
                result.message = Some(err.to_string());
            }
            false
        }
    };

    if ok {
        result.status = "ok".into();
        return result;
    }
    if !do_repair {
        if result.status == "unknown" {
            result.status = "fail".into();
        }
        return result;
    }

    let target = match safe_target_path(path, safe) {
        Ok(target) => target,
        Err(err) => {
            result.status = "fail".into();
            result.message = Some(err.to_string());
            return result;
        }
    };

    let repair = match if safe {
        repair_archive(path, password, keyfile, Some(&target))
    } else {
        repair_archive(path, password, keyfile, None)
    } {
        Ok(repair) => repair,
        Err(err) => {
            result.status = "fail".into();
            result.message = Some(err.to_string());
            return result;
        }
    };
    result.global_fixed = repair.amcf_repaired.len();

    match verify_archive(&target, password, keyfile) {
        Ok(summary) if summary.ok => {}
        Ok(_) => {
            result.status = "fail".into();
            return result;
        }
        Err(err) => {
            result.status = "fail".into();
            result.message = Some(err.to_string());
            return result;
        }
    }

    if harden_ppm > 0 {
        match append_amcf_parity(&target, harden_ppm, password, keyfile) {
            Ok(added) => result.harden_added = added,
            Err(err) => {
                result.status = "fail".into();
                result.message = Some(err.to_string());
                return result;
            }
        }
    }
    result.status = "repaired".into();
    result
}

fn safe_target_path(path: &Path, safe: bool) -> AmberResult<PathBuf> {
    if !safe {
        return canonical_archive_base_path(path);
    }
    default_repaired_output_path(path)
}

fn is_locked_error(path: &Path, err: &AmberError) -> bool {
    if matches!(err, AmberError::EncryptedIndexRequiresPassword(_)) {
        return true;
    }
    if !is_encrypted_archive(path) {
        return false;
    }
    let message = err.to_string().to_ascii_lowercase();
    message.contains("decryption failed")
        || message.contains("mac check failed")
        || message.contains("index frame crc mismatch")
        || message.contains("encrypted payload too short")
}

fn is_encrypted_archive(path: &Path) -> bool {
    let Ok(segment_paths) = discover_archive_segment_paths(path) else {
        return false;
    };
    let Some(first_segment) = segment_paths.first() else {
        return false;
    };
    let mut raw = match std::fs::File::open(first_segment) {
        Ok(raw) => raw,
        Err(_) => return false,
    };
    match crate::superblock::read_superblock(&mut raw) {
        Ok(superblock) => (superblock.flags & FLAG_ENCRYPTED) != 0,
        Err(_) => false,
    }
}

fn safe_destination(base_outdir: &Path, archive_path: &str) -> AmberResult<PathBuf> {
    let normalized = archive_path.replace('\\', "/");
    if normalized.starts_with('/') || normalized.starts_with('\\') {
        return Err(AmberError::Invalid(format!(
            "Refusing to extract absolute archive path: {archive_path:?}"
        )));
    }
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>();
    if parts.iter().any(|part| *part == "..") {
        return Err(AmberError::Invalid(format!(
            "Refusing to extract path with '..': {archive_path:?}"
        )));
    }
    let mut out = base_outdir.to_path_buf();
    for part in parts {
        out.push(part);
    }
    Ok(out)
}

fn assert_within_outdir(base_outdir: &Path, path: &Path) -> AmberResult<()> {
    let real: PathBuf = fs::canonicalize(path).or_else(|_| -> AmberResult<PathBuf> {
        let parent = path
            .parent()
            .ok_or_else(|| AmberError::Invalid("path is missing parent".into()))?;
        let real_parent = fs::canonicalize(parent)?;
        let file_name = path
            .file_name()
            .ok_or_else(|| AmberError::Invalid("path is missing file name".into()))?;
        Ok(real_parent.join(file_name))
    })?;
    if !real.starts_with(base_outdir) {
        return Err(AmberError::Invalid(format!(
            "Extraction destination escapes outdir: {:?}",
            path
        )));
    }
    Ok(())
}

fn prepare_parent(base_outdir: &Path, path: &Path) -> AmberResult<()> {
    let parent = path.parent().unwrap_or(base_outdir);
    fs::create_dir_all(parent)?;
    assert_within_outdir(base_outdir, parent)
}

fn validate_symlink_destination(
    base_outdir: &Path,
    link_path: &Path,
    target: &str,
) -> AmberResult<()> {
    let norm_target = target.replace('\\', "/");
    if norm_target.starts_with('/')
        || norm_target.starts_with('\\')
        || (norm_target.len() >= 2
            && norm_target.as_bytes()[1] == b':'
            && norm_target.as_bytes()[0].is_ascii_alphabetic())
    {
        return Err(AmberError::Invalid(format!(
            "Refusing to create symlink with absolute target: {target:?}"
        )));
    }
    let link_dir = link_path.parent().unwrap_or(base_outdir);
    let resolved = fs::canonicalize(link_dir)
        .unwrap_or_else(|_| link_dir.to_path_buf())
        .join(Path::new(&norm_target));
    let normalized = normalize_path(&resolved);
    if !normalized.starts_with(base_outdir) {
        return Err(AmberError::Invalid(format!(
            "Symlink target escapes outdir: {target:?}"
        )));
    }
    Ok(())
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn resolve_existing_destination(
    base_outdir: &Path,
    path: &Path,
    exists: ExistsMode,
    summary: &mut UnsealSummary,
    is_symlink: bool,
) -> AmberResult<Option<PathBuf>> {
    let exists_now = path.exists() || fs::symlink_metadata(path).is_ok();
    if !exists_now {
        return Ok(Some(path.to_path_buf()));
    }
    match exists {
        ExistsMode::Overwrite => {
            if path.is_dir() && !fs::symlink_metadata(path)?.file_type().is_symlink() {
                return Err(AmberError::Invalid(format!(
                    "Cannot overwrite directory with {}: {}",
                    if is_symlink { "symlink" } else { "file" },
                    path.display()
                )));
            }
            if fs::symlink_metadata(path)?.file_type().is_symlink() || path.is_file() {
                fs::remove_file(path)?;
            }
            Ok(Some(path.to_path_buf()))
        }
        ExistsMode::Skip => {
            summary.skipped_entries += 1;
            Ok(None)
        }
        ExistsMode::Rename => {
            let renamed = next_nonconflicting_path(base_outdir, path)?;
            summary.renamed_entries += 1;
            Ok(Some(renamed))
        }
        ExistsMode::Fail => Err(AmberError::Invalid(format!(
            "Destination exists: {}",
            path.display()
        ))),
    }
}

fn next_nonconflicting_path(base_outdir: &Path, path: &Path) -> AmberResult<PathBuf> {
    let parent = path.parent().unwrap_or(base_outdir);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AmberError::Invalid("destination path must be valid UTF-8".into()))?;
    let (root, ext) = match name.rsplit_once('.') {
        Some((root, ext)) if !root.is_empty() => (root.to_string(), format!(".{ext}")),
        _ => (name.to_string(), String::new()),
    };
    let mut index = 1usize;
    loop {
        let candidate = parent.join(format!("{root} ({index}){ext}"));
        if !candidate.exists() && fs::symlink_metadata(&candidate).is_err() {
            return Ok(candidate);
        }
        index += 1;
    }
}

fn apply_extracted_metadata(
    path: &Path,
    mode: Option<u64>,
    atime_sec: Option<u64>,
    atime_nsec: Option<u64>,
    mtime_sec: Option<u64>,
    mtime_nsec: Option<u64>,
) -> AmberResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = mode {
            fs::set_permissions(path, fs::Permissions::from_mode(mode as u32))?;
        }
    }
    if let Some(mtime_sec) = mtime_sec {
        let atime_sec = atime_sec.unwrap_or(mtime_sec);
        filetime::set_file_times(
            path,
            filetime::FileTime::from_unix_time(atime_sec as i64, atime_nsec.unwrap_or(0) as u32),
            filetime::FileTime::from_unix_time(mtime_sec as i64, mtime_nsec.unwrap_or(0) as u32),
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, path: &Path) -> AmberResult<()> {
    std::os::unix::fs::symlink(target, path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_symlink(_target: &str, _path: &Path) -> AmberResult<()> {
    Err(AmberError::Invalid(
        "symlinks not supported on this platform".into(),
    ))
}

#[cfg(test)]
#[path = "tests/cli.rs"]
mod tests;
