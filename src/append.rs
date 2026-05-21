use std::path::Path;

use crate::error::AmberResult;
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
        Some(&move |_stage_root, staged_entries| {
            append_inputs_into_stage(staged_entries, &owned_inputs)
        }),
    )
}

fn append_inputs_into_stage(
    staged_entries: &mut Vec<StagedEntry>,
    inputs: &[impl AsRef<Path>],
) -> AmberResult<()> {
    let scanned = scan_inputs(inputs)?;

    for dir in scanned.dirs {
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
        staged_entries.push(StagedEntry {
            path: file_input.archive_path,
            kind: 0,
            fs_path: Some(file_input.fs_path),
            mode: file_input.metadata.mode,
            mtime_sec: file_input.metadata.mtime_sec,
            mtime_nsec: file_input.metadata.mtime_nsec,
            atime_sec: file_input.metadata.atime_sec,
            atime_nsec: file_input.metadata.atime_nsec,
            file_codec: None,
            chunk_size: None,
            symlink_target: None,
            size: file_input.size,
        });
    }

    Ok(())
}
