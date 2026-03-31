use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{AmberError, AmberResult};
use crate::pathutil::{validate_archive_path, validate_symlink_target};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InputMetadata {
    pub mode: Option<u64>,
    pub mtime_sec: Option<u64>,
    pub mtime_nsec: Option<u64>,
    pub atime_sec: Option<u64>,
    pub atime_nsec: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryInput {
    pub archive_path: String,
    pub metadata: InputMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkInput {
    pub archive_path: String,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileInput {
    pub archive_path: String,
    pub fs_path: PathBuf,
    pub metadata: InputMetadata,
    pub size: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScannedInputs {
    pub dirs: Vec<DirectoryInput>,
    pub symlinks: Vec<SymlinkInput>,
    pub files: Vec<FileInput>,
}

pub fn scan_inputs(inputs: &[impl AsRef<Path>]) -> AmberResult<ScannedInputs> {
    let mut scanned = ScannedInputs::default();
    for input in inputs {
        let path = input.as_ref();
        if path.is_symlink() {
            scanned.symlinks.push(SymlinkInput {
                archive_path: validate_input_leaf(path)?,
                target: validate_symlink_target(fs::read_link(path)?.to_string_lossy().as_ref())?,
            });
            continue;
        }
        if path.is_dir() {
            let base = validate_input_leaf(path)?;
            scanned.dirs.push(DirectoryInput {
                archive_path: base.clone(),
                metadata: input_metadata(path)?,
            });
            walk_dir(path, path, &base, &mut scanned)?;
            continue;
        }
        let metadata = input_metadata(path)?;
        scanned.files.push(FileInput {
            archive_path: validate_input_leaf(path)?,
            fs_path: absolutize_fs_path(path)?,
            size: fs::metadata(path)?.len(),
            metadata,
        });
    }
    Ok(scanned)
}

fn walk_dir(
    root: &Path,
    current: &Path,
    base: &str,
    scanned: &mut ScannedInputs,
) -> AmberResult<()> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .map_err(|_| AmberError::Invalid("failed to compute relative path".into()))?;
        let arc = validate_archive_path(&format!(
            "{base}/{}",
            rel.to_string_lossy().replace('\\', "/")
        ))?;
        if path.is_symlink() {
            scanned.symlinks.push(SymlinkInput {
                archive_path: arc,
                target: validate_symlink_target(fs::read_link(&path)?.to_string_lossy().as_ref())?,
            });
            continue;
        }
        if path.is_dir() {
            scanned.dirs.push(DirectoryInput {
                archive_path: arc.clone(),
                metadata: input_metadata(&path)?,
            });
            walk_dir(root, &path, base, scanned)?;
            continue;
        }
        let metadata = input_metadata(&path)?;
        scanned.files.push(FileInput {
            archive_path: arc,
            fs_path: absolutize_fs_path(&path)?,
            size: fs::metadata(&path)?.len(),
            metadata,
        });
    }
    Ok(())
}

fn absolutize_fs_path(path: &Path) -> AmberResult<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn validate_input_leaf(path: &Path) -> AmberResult<String> {
    validate_archive_path(
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| AmberError::Invalid("input path must be valid UTF-8".into()))?,
    )
}

fn input_metadata(path: &Path) -> AmberResult<InputMetadata> {
    let st = fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(InputMetadata {
            mode: Some((st.mode() & 0o7777) as u64),
            mtime_sec: Some(st.mtime() as u64),
            mtime_nsec: Some(st.mtime_nsec() as u64),
            atime_sec: Some(st.atime() as u64),
            atime_nsec: Some(st.atime_nsec() as u64),
        });
    }
    #[allow(unreachable_code)]
    {
        let modified = st
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
        let accessed = st
            .accessed()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
        Ok(InputMetadata {
            mode: None,
            mtime_sec: modified.map(|d| d.as_secs()),
            mtime_nsec: modified.map(|d| d.subsec_nanos() as u64),
            atime_sec: accessed.map(|d| d.as_secs()),
            atime_nsec: accessed.map(|d| d.subsec_nanos() as u64),
        })
    }
}
