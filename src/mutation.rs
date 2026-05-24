use std::fs;
use std::path::{Path, PathBuf};

use tempfile::{Builder, TempDir};

use crate::archiveio::{
    assert_archive_output_path_clear, canonical_archive_base_path, copy_archive_set,
    discover_archive_segment_paths, multipart_segment_path, parent_dir_or_dot,
};
use crate::codec::compressed_len_upper_bound;
use crate::constants::FLAG_ENCRYPTED;
use crate::error::{AmberError, AmberResult};
use crate::globalparity::{
    GLOBAL_PARITY_SCHEME_MDS, MIN_TOTAL_PARITY_ROWS_FLOOR, require_canonical_global_parity_scheme,
};
use crate::reader::{ArchiveReader, Entry as ReaderEntry};
use crate::tlv::{get_list, get_map, get_string};
use crate::writer::ArchiveWriter;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EntrySignature {
    pub path: String,
    pub kind: u64,
    pub size: u64,
    pub mode: Option<u64>,
    pub symlink_target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewritePlan {
    pub default_chunk_size: u32,
    pub default_codec: u16,
    pub password: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub part_size: Option<u64>,
    pub mds_epsilon_ppm: usize,
    pub min_total_parity_rows: Option<usize>,
    pub global_parity_scheme: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedEntry {
    pub path: String,
    pub kind: u64,
    pub fs_path: Option<PathBuf>,
    pub mode: Option<u64>,
    pub mtime_sec: Option<u64>,
    pub mtime_nsec: Option<u64>,
    pub atime_sec: Option<u64>,
    pub atime_nsec: Option<u64>,
    pub file_codec: Option<u64>,
    pub chunk_size: Option<u64>,
    pub symlink_target: Option<String>,
    pub size: u64,
}

pub type PlanMutator = dyn Fn(&ArchiveReader, RewritePlan) -> AmberResult<RewritePlan>;
pub type StageMutator = dyn Fn(&Path, &mut Vec<StagedEntry>) -> AmberResult<()>;

pub fn rewrite_archive_to_path(
    source_path: impl AsRef<Path>,
    destination_path: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
    keep_backup: bool,
    backup_suffix: &str,
    plan_mutator: Option<&PlanMutator>,
    stage_mutator: Option<&StageMutator>,
) -> AmberResult<Option<PathBuf>> {
    let source_base_path = canonical_archive_base_path(source_path.as_ref())?;
    let dest_base_path = destination_path.as_ref().to_path_buf();
    let archive_dir = parent_dir_or_dot(&dest_base_path).to_path_buf();
    assert_directory_has_write_permission(&archive_dir)?;
    let temp_output_dir = tempdir_in(&archive_dir, "amber-rewrite-")?;
    let temp_archive_base = temp_output_dir.path().join(
        dest_base_path
            .file_name()
            .ok_or_else(|| AmberError::Invalid("destination path is missing file name".into()))?,
    );
    let stage_root = tempdir("amber-rewrite-stage-")?;

    let result = (|| -> AmberResult<Option<PathBuf>> {
        let mut reader = ArchiveReader::new_with_credentials(
            &source_base_path,
            password.map(str::to_owned),
            keyfile.map(Path::to_path_buf),
        );
        reader.open()?;
        let sb = reader
            .superblock
            .clone()
            .ok_or_else(|| AmberError::Rebuild("Missing superblock in source archive".into()))?;
        let is_encrypted = (sb.flags & FLAG_ENCRYPTED) != 0;
        let mut plan = RewritePlan {
            default_chunk_size: sb.default_chunk_size,
            default_codec: sb.default_codec as u16,
            password: if is_encrypted {
                password.map(str::to_owned)
            } else {
                None
            },
            keyfile: if is_encrypted {
                keyfile.map(Path::to_path_buf)
            } else {
                None
            },
            part_size: if sb.multipart_part_size == 0 {
                None
            } else {
                Some(sb.multipart_part_size)
            },
            mds_epsilon_ppm: infer_mds_epsilon(&reader),
            min_total_parity_rows: Some(infer_total_parity_rows(&reader)),
            global_parity_scheme: infer_global_parity_scheme(&reader)?,
        };
        if let Some(plan_mutator) = plan_mutator {
            plan = plan_mutator(&reader, plan)?;
        }

        let source_snapshot = snapshot_entries(reader.list());
        let mut staged_entries = Vec::new();
        if let Some(stage_mutator) = stage_mutator {
            stage_mutator(stage_root.path(), &mut staged_entries)?;
        }

        validate_no_staged_path_conflicts(reader.list(), &staged_entries)?;
        let expected_snapshot = combined_snapshot(&source_snapshot, &staged_entries);
        let mut writer = ArchiveWriter::new(
            &temp_archive_base,
            Some(plan.default_chunk_size),
            Some(plan.default_codec),
            plan.password.as_deref(),
            plan.keyfile.as_deref(),
            plan.part_size,
            Some(plan.mds_epsilon_ppm),
            plan.min_total_parity_rows,
            Some(&plan.global_parity_scheme),
            None,
        )?;
        writer.configure_symbol_size_for_payload_bound(rewrite_payload_bytes_upper_bound(
            reader.list(),
            &staged_entries,
            plan.default_chunk_size as u64,
            plan.default_codec,
            plan.password.is_some() || plan.keyfile.is_some(),
        )?)?;
        writer.open()?;
        write_source_entries(&mut reader, &mut writer)?;
        write_staged_entries(&staged_entries, &mut writer)?;
        writer.finalize()?;
        writer.close();
        drop(reader);

        let rebuilt_segment_paths = discover_archive_segment_paths(&temp_archive_base)?;
        let rebuilt_base = rebuilt_segment_paths
            .first()
            .cloned()
            .ok_or_else(|| AmberError::Rebuild("rebuilt archive is missing segments".into()))?;
        let mut rebuilt_reader = ArchiveReader::new_with_credentials(
            &rebuilt_base,
            plan.password.clone(),
            plan.keyfile.clone(),
        );
        rebuilt_reader.open()?;
        if !rebuilt_reader.verify()? {
            return Err(AmberError::Rebuild(
                "Verification failed on rebuilt archive".into(),
            ));
        }
        let rebuilt_snapshot = snapshot_entries(rebuilt_reader.list());
        if rebuilt_snapshot != expected_snapshot {
            return Err(AmberError::Rebuild(
                "Rebuilt archive contents differ from staged source".into(),
            ));
        }
        commit_archive_set(
            &dest_base_path,
            &rebuilt_segment_paths,
            keep_backup,
            backup_suffix,
        )
    })();

    result
}

pub fn rewrite_archive_in_place(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
    plan_mutator: Option<&PlanMutator>,
    stage_mutator: Option<&StageMutator>,
) -> AmberResult<()> {
    let destination = canonical_archive_base_path(archive_path.as_ref())?;
    rewrite_archive_to_path(
        archive_path,
        destination,
        password,
        keyfile,
        false,
        ".bak",
        plan_mutator,
        stage_mutator,
    )?;
    Ok(())
}

pub fn mutate_archive_via_work_copy<T, WorkMutator, CommitDecider>(
    source_path: impl AsRef<Path>,
    destination_path: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
    work_mutator: WorkMutator,
    commit_decider: Option<CommitDecider>,
) -> AmberResult<T>
where
    WorkMutator: FnOnce(&Path) -> AmberResult<T>,
    CommitDecider: Fn(&T) -> bool,
{
    let source_base = match canonical_archive_base_path(source_path.as_ref()) {
        Ok(path) => path,
        Err(AmberError::NotFound(_)) => source_path.as_ref().to_path_buf(),
        Err(err) => return Err(err),
    };
    let workdir = tempdir_in(
        parent_dir_or_dot(&source_base),
        "amber-mutate-work-",
    )?;
    let work_base = workdir.path().join(
        source_base
            .file_name()
            .ok_or_else(|| AmberError::Invalid("source path is missing file name".into()))?,
    );
    copy_archive_set(source_path.as_ref(), &work_base)?;
    let outcome = (|| -> AmberResult<T> {
        let value = work_mutator(&work_base)?;
        if let Some(commit_decider) = commit_decider
            && !commit_decider(&value)
        {
            return Ok(value);
        }
        rewrite_archive_to_path(
            &work_base,
            destination_path,
            password,
            keyfile,
            false,
            ".bak",
            None,
            None,
        )?;
        Ok(value)
    })();
    outcome
}

pub fn rebuild_archive(
    path: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
    backup_suffix: &str,
) -> AmberResult<PathBuf> {
    let dest = canonical_archive_base_path(path.as_ref())?;
    rewrite_archive_to_path(
        path,
        dest,
        password,
        keyfile,
        true,
        backup_suffix,
        None,
        None,
    )?
    .ok_or_else(|| AmberError::Rebuild("Expected rebuild backup path".into()))
}

fn snapshot_entries(entries: &[ReaderEntry]) -> Vec<EntrySignature> {
    let mut snap = entries
        .iter()
        .map(|entry| EntrySignature {
            path: entry.path.clone(),
            kind: entry.kind,
            size: if entry.kind == 0 { entry.size } else { 0 },
            mode: entry.mode,
            symlink_target: entry.symlink_target.clone(),
        })
        .collect::<Vec<_>>();
    snap.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    snap
}

fn snapshot_staged_entries(entries: &[StagedEntry]) -> Vec<EntrySignature> {
    let mut snap = entries
        .iter()
        .map(|entry| EntrySignature {
            path: entry.path.clone(),
            kind: entry.kind,
            size: if entry.kind == 0 { entry.size } else { 0 },
            mode: entry.mode,
            symlink_target: entry.symlink_target.clone(),
        })
        .collect::<Vec<_>>();
    snap.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    snap
}

fn combined_snapshot(
    source_snapshot: &[EntrySignature],
    staged_entries: &[StagedEntry],
) -> Vec<EntrySignature> {
    let mut snap = source_snapshot.to_vec();
    snap.extend(snapshot_staged_entries(staged_entries));
    snap.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    snap
}

fn validate_no_staged_path_conflicts(
    source_entries: &[ReaderEntry],
    staged_entries: &[StagedEntry],
) -> AmberResult<()> {
    let mut paths = source_entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for entry in staged_entries {
        if !paths.insert(entry.path.clone()) {
            return Err(AmberError::Invalid(format!(
                "archive path already exists: {}",
                entry.path
            )));
        }
    }
    Ok(())
}

fn infer_mds_epsilon(reader: &ArchiveReader) -> usize {
    let total_data = reader.symbols.iter().filter(|info| !info.is_parity).count();
    if total_data == 0 {
        return 0;
    }
    let target = reader.mds_parities.len();
    if target == 0 {
        return 0;
    }
    (target * 1_000_000).div_ceil(total_data)
}

fn infer_total_parity_rows(reader: &ArchiveReader) -> usize {
    let data_count = reader.symbols.iter().filter(|info| !info.is_parity).count();
    if data_count == 0 {
        return 0;
    }
    reader.mds_parities.len().max(MIN_TOTAL_PARITY_ROWS_FLOOR)
}

fn infer_global_parity_scheme(reader: &ArchiveReader) -> AmberResult<String> {
    let has_ecc_symbols = reader.symbols.iter().any(|symbol| symbol.is_parity);
    if !has_ecc_symbols && reader.mds_parities.is_empty() {
        return Ok(GLOBAL_PARITY_SCHEME_MDS.into());
    }
    let Some(index) = reader.index.as_ref() else {
        return Err(AmberError::Invalid(
            "archive with parity symbols is missing index metadata".into(),
        ));
    };
    let Some(groups) = get_list(index, "ecc_groups") else {
        return Err(AmberError::Invalid(
            "archive with parity symbols is missing ECC group metadata".into(),
        ));
    };
    let Some(group) = groups
        .iter()
        .filter(|group| get_map(group, "mds").is_some())
        .max_by_key(|group| crate::tlv::get_u64(group, "group_id").unwrap_or(0))
    else {
        return Err(AmberError::Invalid(
            "archive with parity symbols is missing MDS metadata".into(),
        ));
    };
    let Some(mds) = get_map(group, "mds") else {
        return Err(AmberError::Invalid(
            "archive with parity symbols is missing MDS metadata".into(),
        ));
    };
    let Some(stored_scheme) = get_string(mds, "scheme") else {
        return Err(AmberError::Invalid("MDS metadata is missing its scheme".into()));
    };
    Ok(require_canonical_global_parity_scheme(stored_scheme)
        .map_err(AmberError::Invalid)?
        .to_owned())
}

fn rewrite_payload_bytes_upper_bound(
    source_entries: &[ReaderEntry],
    staged_entries: &[StagedEntry],
    default_chunk_size: u64,
    default_codec: u16,
    encrypted: bool,
) -> AmberResult<u64> {
    let mut total = 0u64;
    for entry in source_entries {
        if entry.kind != 0 {
            continue;
        }
        let codec_id = entry
            .file_codec
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(default_codec);
        let chunk_size = entry.chunk_size.unwrap_or(default_chunk_size);
        total = total
            .checked_add(entry_payload_bytes_upper_bound(
                entry.size, chunk_size, codec_id, encrypted,
            )?)
            .ok_or_else(|| AmberError::Invalid("archive payload size bound overflow".into()))?;
    }
    for entry in staged_entries {
        if entry.kind != 0 {
            continue;
        }
        let codec_id = entry
            .file_codec
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(default_codec);
        let chunk_size = entry.chunk_size.unwrap_or(default_chunk_size);
        total = total
            .checked_add(entry_payload_bytes_upper_bound(
                entry.size, chunk_size, codec_id, encrypted,
            )?)
            .ok_or_else(|| AmberError::Invalid("archive payload size bound overflow".into()))?;
    }
    Ok(total)
}

fn entry_payload_bytes_upper_bound(
    size: u64,
    chunk_size: u64,
    codec_id: u16,
    encrypted: bool,
) -> AmberResult<u64> {
    if size == 0 {
        return Ok(0);
    }
    let chunks = size.div_ceil(chunk_size.max(1));
    let mut bytes = 0u64;
    for chunk in 0..chunks {
        let offset = chunk.saturating_mul(chunk_size);
        let raw_len = (size - offset).min(chunk_size);
        bytes = bytes
            .checked_add(compressed_len_upper_bound(codec_id, raw_len)?)
            .ok_or_else(|| AmberError::Invalid("stored payload size bound overflow".into()))?;
    }
    if encrypted {
        bytes = bytes
            .checked_add(chunks.saturating_mul(16))
            .ok_or_else(|| AmberError::Invalid("encrypted payload size bound overflow".into()))?;
    }
    Ok(bytes)
}

fn write_source_entries(reader: &mut ArchiveReader, writer: &mut ArchiveWriter) -> AmberResult<()> {
    let entries = reader.list().to_vec();
    let mut dirs = entries
        .iter()
        .filter(|entry| entry.kind == 1)
        .cloned()
        .collect::<Vec<_>>();
    dirs.sort_by_key(|entry| (entry.path.matches('/').count(), entry.path.clone()));
    for entry in dirs {
        writer.add_dir(
            &entry.path,
            entry.mode,
            entry.mtime_sec,
            entry.mtime_nsec,
            entry.atime_sec,
            entry.atime_nsec,
        )?;
    }

    let mut symlinks = entries
        .iter()
        .filter(|entry| entry.kind == 2)
        .cloned()
        .collect::<Vec<_>>();
    symlinks.sort_by_key(|entry| entry.path.clone());
    for entry in symlinks {
        let target = entry.symlink_target.as_deref().ok_or_else(|| {
            AmberError::Rebuild(format!("Source symlink is missing target: {}", entry.path))
        })?;
        writer.add_symlink(&entry.path, target)?;
    }

    let mut files = entries
        .iter()
        .filter(|entry| entry.kind == 0)
        .cloned()
        .collect::<Vec<_>>();
    files.sort_by_key(|entry| entry.path.clone());
    for entry in files {
        writer.add_file_from_archive_entry(reader, &entry)?;
    }
    Ok(())
}

fn write_staged_entries(entries: &[StagedEntry], writer: &mut ArchiveWriter) -> AmberResult<()> {
    let mut dir_entries = entries
        .iter()
        .filter(|entry| entry.kind == 1)
        .cloned()
        .collect::<Vec<_>>();
    dir_entries.sort_by_key(|entry| (entry.path.matches('/').count(), entry.path.clone()));
    for entry in dir_entries {
        writer.add_dir(
            &entry.path,
            entry.mode,
            entry.mtime_sec,
            entry.mtime_nsec,
            entry.atime_sec,
            entry.atime_nsec,
        )?;
    }

    let mut symlink_entries = entries
        .iter()
        .filter(|entry| entry.kind == 2)
        .cloned()
        .collect::<Vec<_>>();
    symlink_entries.sort_by_key(|entry| entry.path.clone());
    for entry in symlink_entries {
        writer.add_symlink(&entry.path, entry.symlink_target.as_deref().unwrap_or(""))?;
    }

    let mut file_entries = entries
        .iter()
        .filter(|entry| entry.kind == 0)
        .cloned()
        .collect::<Vec<_>>();
    file_entries.sort_by_key(|entry| entry.path.clone());
    for entry in file_entries {
        let fs_path = entry.fs_path.as_ref().ok_or_else(|| {
            AmberError::Rebuild(format!(
                "Staged file is missing a source path: {}",
                entry.path
            ))
        })?;
        let codec_id = entry
            .file_codec
            .map(|value| {
                u16::try_from(value).map_err(|_| {
                    AmberError::Rebuild(format!(
                        "Staged file codec does not fit in u16: {} ({value})",
                        entry.path
                    ))
                })
            })
            .transpose()?;
        let chunk_size = entry
            .chunk_size
            .map(|value| {
                u32::try_from(value).map_err(|_| {
                    AmberError::Rebuild(format!(
                        "Staged chunk_size does not fit in u32: {} ({value})",
                        entry.path
                    ))
                })
            })
            .transpose()?;
        writer.add_file_with_metadata(
            &entry.path,
            fs_path,
            codec_id,
            chunk_size,
            entry.mode,
            entry.mtime_sec,
            entry.mtime_nsec,
            entry.atime_sec,
            entry.atime_nsec,
        )?;
    }
    Ok(())
}

fn commit_archive_set(
    dest_base_path: &Path,
    rebuilt_segment_paths: &[PathBuf],
    keep_backup: bool,
    backup_suffix: &str,
) -> AmberResult<Option<PathBuf>> {
    let existing_paths = resolve_existing_archive_paths(dest_base_path)?;
    let final_paths = final_archive_paths(dest_base_path, rebuilt_segment_paths.len())?;
    let archive_dir = parent_dir_or_dot(dest_base_path);

    let (backup_paths, _cleanup_dir) = if keep_backup {
        if existing_paths.len() == 1 {
            let backup_base = archive_dir.join(format!(
                "{}{}",
                dest_base_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| AmberError::Invalid(
                        "destination path must be valid UTF-8".into()
                    ))?,
                backup_suffix
            ));
            assert_archive_output_path_clear(&backup_base, false)?;
            (vec![backup_base], None)
        } else {
            let base = PathBuf::from(format!("{}{}", dest_base_path.display(), backup_suffix));
            assert_archive_output_path_clear(&base, true)?;
            (
                (0..existing_paths.len())
                    .map(|index| multipart_segment_path(&base, index as u32 + 1))
                    .collect::<AmberResult<Vec<_>>>()?,
                None,
            )
        }
    } else {
        let cleanup_dir = tempdir_in(archive_dir, "amber-commit-")?;
        let backup_paths = existing_paths
            .iter()
            .map(|path| {
                let file_name = path.file_name().ok_or_else(|| {
                    AmberError::Invalid("archive segment is missing file name".into())
                })?;
                Ok(cleanup_dir.path().join(file_name))
            })
            .collect::<AmberResult<Vec<_>>>()?;
        (backup_paths, Some(cleanup_dir))
    };

    let mut committed_sources = Vec::new();
    let mut committed_targets = Vec::new();
    let result = (|| -> AmberResult<Option<PathBuf>> {
        for (source_path, backup_path) in existing_paths.iter().zip(backup_paths.iter()) {
            replace_path(source_path, backup_path)?;
            committed_sources.push((source_path.clone(), backup_path.clone()));
        }
        for (rebuilt_path, final_path) in rebuilt_segment_paths.iter().zip(final_paths.iter()) {
            replace_path(rebuilt_path, final_path)?;
            committed_targets.push((rebuilt_path.clone(), final_path.clone()));
        }
        Ok(if keep_backup {
            backup_paths.first().cloned()
        } else {
            None
        })
    })();

    if result.is_err() {
        for (_, final_path) in committed_targets.iter().rev() {
            let _ = fs::remove_file(final_path);
        }
        for (source_path, backup_path) in committed_sources.iter().rev() {
            if !source_path.exists() && backup_path.exists() {
                let _ = replace_path(backup_path, source_path);
            }
        }
    }
    result
}

fn resolve_existing_archive_paths(base_path: &Path) -> AmberResult<Vec<PathBuf>> {
    match discover_archive_segment_paths(base_path) {
        Ok(paths) => Ok(paths),
        Err(AmberError::NotFound(_)) => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

fn final_archive_paths(base_path: &Path, segment_count: usize) -> AmberResult<Vec<PathBuf>> {
    if segment_count == 1 {
        return Ok(vec![base_path.to_path_buf()]);
    }
    (0..segment_count)
        .map(|index| multipart_segment_path(base_path, index as u32 + 1))
        .collect()
}

fn tempdir(prefix: &str) -> AmberResult<TempDir> {
    tempdir_in(Path::new(&std::env::temp_dir()), prefix)
}

#[cfg(unix)]
fn assert_directory_has_write_permission(path: &Path) -> AmberResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o222 == 0 {
        return Err(AmberError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Permission denied: {}", path.display()),
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_directory_has_write_permission(_path: &Path) -> AmberResult<()> {
    Ok(())
}

fn tempdir_in(base: &Path, prefix: &str) -> AmberResult<TempDir> {
    Builder::new()
        .prefix(prefix)
        .tempdir_in(base)
        .map_err(AmberError::Io)
}

#[cfg(windows)]
fn replace_path(source: &Path, target: &Path) -> AmberResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MoveFileExW};

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let source_w = wide(source);
    let target_w = wide(target);
    let result = unsafe {
        MoveFileExW(
            source_w.as_ptr(),
            target_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING,
        )
    };
    if result == 0 {
        return Err(AmberError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_path(source: &Path, target: &Path) -> AmberResult<()> {
    fs::rename(source, target)?;
    Ok(())
}

#[cfg(test)]
#[path = "tests/mutation.rs"]
mod tests;
