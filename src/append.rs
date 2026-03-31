use std::fs;
use std::path::Path;

use filetime::{FileTime, set_file_times};

use crate::error::{AmberError, AmberResult};
use crate::inputscan::scan_inputs;
use crate::mutation::{StagedEntry, rewrite_archive_in_place};

pub fn append_to_archive(
    archive_path: impl AsRef<Path>,
    inputs: &[impl AsRef<Path>],
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<()> {
    let owned_inputs = inputs
        .iter()
        .map(|path| path.as_ref().to_path_buf())
        .collect::<Vec<_>>();
    rewrite_archive_in_place(
        archive_path,
        password,
        keyfile,
        None,
        Some(&move |stage_root, staged_entries| {
            append_inputs_into_stage(stage_root, staged_entries, &owned_inputs)
        }),
    )
}

fn append_inputs_into_stage(
    stage_root: &Path,
    staged_entries: &mut Vec<StagedEntry>,
    inputs: &[impl AsRef<Path>],
) -> AmberResult<()> {
    let scanned = scan_inputs(inputs)?;

    for dir in scanned.dirs {
        let target = stage_root.join(&dir.archive_path);
        if target.exists() || symlink_metadata_exists(&target) {
            return Err(AmberError::Invalid(format!(
                "archive path already exists: {}",
                dir.archive_path
            )));
        }
        fs::create_dir_all(&target)?;
        apply_regular_metadata(
            &target,
            dir.metadata.mode,
            dir.metadata.mtime_sec,
            dir.metadata.atime_sec,
        )?;
        staged_entries.push(StagedEntry {
            path: dir.archive_path,
            kind: 1,
            fs_path: None,
            mode: dir.metadata.mode,
            mtime_sec: dir.metadata.mtime_sec,
            mtime_nsec: dir.metadata.mtime_nsec,
            atime_sec: dir.metadata.atime_sec,
            atime_nsec: dir.metadata.atime_nsec,
            file_codec: None,
            chunk_size: None,
            symlink_target: None,
            size: 0,
        });
    }

    for symlink_input in scanned.symlinks {
        let target = stage_root.join(&symlink_input.archive_path);
        if target.exists() || symlink_metadata_exists(&target) {
            return Err(AmberError::Invalid(format!(
                "archive path already exists: {}",
                symlink_input.archive_path
            )));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        symlink(&symlink_input.target, &target)?;
        staged_entries.push(StagedEntry {
            path: symlink_input.archive_path,
            kind: 2,
            fs_path: None,
            mode: None,
            mtime_sec: None,
            mtime_nsec: None,
            atime_sec: None,
            atime_nsec: None,
            file_codec: None,
            chunk_size: None,
            symlink_target: Some(symlink_input.target),
            size: 0,
        });
    }

    for file_input in scanned.files {
        let target = stage_root.join(&file_input.archive_path);
        if target.exists() || symlink_metadata_exists(&target) {
            return Err(AmberError::Invalid(format!(
                "archive path already exists: {}",
                file_input.archive_path
            )));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&file_input.fs_path, &target)?;
        apply_regular_metadata(
            &target,
            file_input.metadata.mode,
            file_input.metadata.mtime_sec,
            file_input.metadata.atime_sec,
        )?;
        staged_entries.push(StagedEntry {
            path: file_input.archive_path,
            kind: 0,
            fs_path: Some(target.clone()),
            mode: file_input.metadata.mode,
            mtime_sec: file_input.metadata.mtime_sec,
            mtime_nsec: file_input.metadata.mtime_nsec,
            atime_sec: file_input.metadata.atime_sec,
            atime_nsec: file_input.metadata.atime_nsec,
            file_codec: None,
            chunk_size: None,
            symlink_target: None,
            size: fs::metadata(&target)?.len(),
        });
    }

    Ok(())
}

fn apply_regular_metadata(
    path: &Path,
    mode: Option<u64>,
    mtime_sec: Option<u64>,
    atime_sec: Option<u64>,
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
        set_file_times(
            path,
            FileTime::from_unix_time(atime_sec as i64, 0),
            FileTime::from_unix_time(mtime_sec as i64, 0),
        )?;
    }
    Ok(())
}

fn symlink_metadata_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[cfg(unix)]
fn symlink(target: &str, path: &Path) -> AmberResult<()> {
    std::os::unix::fs::symlink(target, path)?;
    Ok(())
}

#[cfg(not(unix))]
fn symlink(_target: &str, _path: &Path) -> AmberResult<()> {
    Err(AmberError::Invalid(
        "symlink staging is unsupported on this platform".into(),
    ))
}
