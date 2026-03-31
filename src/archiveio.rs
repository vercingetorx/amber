use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{AmberError, AmberResult};
use crate::records::RecordWriteTarget;
use crate::superblock::{SUPERBLOCK_SIZE, read_superblock};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSegment {
    pub path: PathBuf,
    pub logical_start: u64,
    pub logical_length: u64,
    pub physical_header_length: u64,
}

impl ArchiveSegment {
    pub fn logical_end(&self) -> u64 {
        self.logical_start + self.logical_length
    }

    pub fn physical_length(&self) -> u64 {
        self.physical_header_length + self.logical_length
    }

    pub fn logical_to_physical(&self, logical_offset: u64) -> AmberResult<u64> {
        if logical_offset < self.logical_start || logical_offset >= self.logical_end() {
            return Err(AmberError::Invalid("logical offset outside segment".into()));
        }
        Ok(self.physical_header_length + (logical_offset - self.logical_start))
    }
}

pub fn multipart_segment_path(base_path: &Path, segment_index: u32) -> AmberResult<PathBuf> {
    if segment_index < 1 {
        return Err(AmberError::Invalid("segment_index must be >= 1".into()));
    }
    Ok(PathBuf::from(format!(
        "{}.{segment_index:03}",
        base_path.display()
    )))
}

pub fn is_multipart_segment_path(path: &Path) -> bool {
    parse_segment_path(path).is_some()
}

pub fn discover_archive_segment_paths(path: &Path) -> AmberResult<Vec<PathBuf>> {
    if let Some(base) = parse_segment_path(path).map(|(base, _)| base) {
        return discover_multipart_segment_paths(&base);
    }
    if multipart_namespace_exists(path)? {
        if path.is_file() {
            return Err(AmberError::Invalid(format!(
                "ambiguous archive path: both single-file archive and multipart archive set exist for {}",
                path.display()
            )));
        }
        return discover_multipart_segment_paths(path);
    }
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    Err(AmberError::NotFound(path.display().to_string()))
}

pub fn canonical_archive_base_path(path: &Path) -> AmberResult<PathBuf> {
    let segment_paths = discover_archive_segment_paths(path)?;
    if segment_paths.len() == 1 {
        return Ok(segment_paths[0].clone());
    }
    let (base, _) = parse_segment_path(&segment_paths[0]).ok_or_else(|| {
        AmberError::Invalid("multipart segment path does not follow canonical naming".into())
    })?;
    Ok(base)
}

pub fn assert_archive_output_path_clear(base_path: &Path, multipart: bool) -> AmberResult<()> {
    if parse_segment_path(base_path).is_some() {
        return Err(AmberError::Invalid(
            "archive output path must be the base archive path, not a numbered segment".into(),
        ));
    }
    let mut conflicting_paths = Vec::new();
    if base_path.exists() {
        conflicting_paths.push(base_path.to_path_buf());
    }
    conflicting_paths.extend(
        discover_all_multipart_segment_paths(base_path)?
            .into_iter()
            .map(|(_, path)| path),
    );
    if conflicting_paths.is_empty() {
        return Ok(());
    }
    let noun = if multipart {
        "multipart archive set"
    } else {
        "archive path"
    };
    let joined = conflicting_paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(AmberError::Exists(format!(
        "{noun} already exists for {}: {joined}",
        base_path.display()
    )))
}

pub fn parent_dir_or_dot(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn parse_segment_path(path: &Path) -> Option<(PathBuf, u32)> {
    let file_name = path.file_name()?.to_str()?;
    let idx = file_name.rfind('.')?;
    let suffix = &file_name[idx + 1..];
    if suffix.len() != 3 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut base = path.to_path_buf();
    base.set_file_name(&file_name[..idx]);
    let segment_index = suffix.parse().ok()?;
    Some((base, segment_index))
}

fn discover_multipart_segment_paths(base_path: &Path) -> AmberResult<Vec<PathBuf>> {
    let mut discovered = discover_all_multipart_segment_paths(base_path)?;
    if discovered.is_empty() {
        return Err(AmberError::NotFound(base_path.display().to_string()));
    }

    discovered.sort_by_key(|(idx, _)| *idx);
    if discovered[0].0 != 1 {
        return Err(AmberError::NotFound(base_path.display().to_string()));
    }

    let mut out = Vec::with_capacity(discovered.len());
    let mut expected = 1u32;
    for (segment_index, segment_path) in discovered {
        if segment_index != expected {
            return Err(AmberError::Invalid(format!(
                "multipart segment gap detected: expected .{expected:03} but found .{segment_index:03}"
            )));
        }
        out.push(segment_path);
        expected += 1;
    }
    Ok(out)
}

fn discover_all_multipart_segment_paths(base_path: &Path) -> AmberResult<Vec<(u32, PathBuf)>> {
    let base_dir = parent_dir_or_dot(base_path);
    let base_name = base_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AmberError::Invalid("archive path must be valid UTF-8".into()))?;
    let prefix = format!("{base_name}.");

    let mut out = Vec::new();
    for entry in fs::read_dir(base_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let suffix = &name[prefix.len()..];
        if suffix.len() != 3 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let candidate = entry.path();
        if !candidate.is_file() {
            continue;
        }
        out.push((suffix.parse().unwrap(), candidate));
    }
    out.sort_by_key(|(idx, _)| *idx);
    Ok(out)
}

fn multipart_namespace_exists(base_path: &Path) -> AmberResult<bool> {
    Ok(!discover_all_multipart_segment_paths(base_path)?.is_empty())
}

#[derive(Debug)]
pub struct LogicalArchiveReader {
    handles: Vec<File>,
    segments: Vec<ArchiveSegment>,
    pos: u64,
}

impl LogicalArchiveReader {
    pub fn new(handles: Vec<File>, segments: Vec<ArchiveSegment>) -> AmberResult<Self> {
        if handles.is_empty() {
            return Err(AmberError::Invalid(
                "Logical archive requires at least one segment".into(),
            ));
        }
        if handles.len() != segments.len() {
            return Err(AmberError::Invalid("handle/segment count mismatch".into()));
        }
        let mut expected_start = 0u64;
        for segment in &segments {
            if segment.logical_start != expected_start {
                return Err(AmberError::Invalid(
                    "segments must be contiguous in logical space".into(),
                ));
            }
            expected_start = segment.logical_end();
        }
        Ok(Self {
            handles,
            segments,
            pos: 0,
        })
    }

    pub fn open_single(path: &Path) -> AmberResult<Self> {
        let handle = File::open(path)?;
        let size = handle.metadata()?.len();
        Self::new(
            vec![handle],
            vec![ArchiveSegment {
                path: path.to_path_buf(),
                logical_start: 0,
                logical_length: size,
                physical_header_length: 0,
            }],
        )
    }

    pub fn open_single_rw(path: &Path) -> AmberResult<Self> {
        let handle = OpenOptions::new().read(true).write(true).open(path)?;
        let size = handle.metadata()?.len();
        Self::new(
            vec![handle],
            vec![ArchiveSegment {
                path: path.to_path_buf(),
                logical_start: 0,
                logical_length: size,
                physical_header_length: 0,
            }],
        )
    }

    pub fn open_path(path: &Path) -> AmberResult<Self> {
        Self::open_path_with_mode(path, false)
    }

    pub fn open_path_rw(path: &Path) -> AmberResult<Self> {
        Self::open_path_with_mode(path, true)
    }

    fn open_path_with_mode(path: &Path, write: bool) -> AmberResult<Self> {
        let segment_paths = discover_archive_segment_paths(path)?;
        if segment_paths.len() == 1 {
            return if write {
                Self::open_single_rw(&segment_paths[0])
            } else {
                Self::open_single(&segment_paths[0])
            };
        }

        let mut handles = Vec::new();
        let mut segments = Vec::new();
        let mut logical_start = 0u64;
        let mut archive_uuid = None;
        let mut multipart_part_size = None;

        for (idx, segment_path) in segment_paths.iter().enumerate() {
            let handle = OpenOptions::new()
                .read(true)
                .write(write)
                .open(segment_path)?;
            let size = handle.metadata()?.len();
            let mut sb_handle = File::open(segment_path)?;
            let superblock = read_superblock(&mut sb_handle)?;
            match archive_uuid {
                None => {
                    archive_uuid = Some(superblock.uuid);
                    multipart_part_size = match superblock.multipart_part_size {
                        0 => None,
                        value => Some(value),
                    };
                }
                Some(uuid) if uuid != superblock.uuid => {
                    return Err(AmberError::Invalid(
                        "Multipart segment archive UUID mismatch".into(),
                    ));
                }
                Some(_) if superblock.multipart_part_size != multipart_part_size.unwrap_or(0) => {
                    return Err(AmberError::Invalid(
                        "Multipart segment part-size policy mismatch".into(),
                    ));
                }
                _ => {}
            }

            let (physical_header_length, logical_length) = if idx == 0 {
                (0u64, size)
            } else {
                if size < SUPERBLOCK_SIZE as u64 {
                    return Err(AmberError::Invalid(
                        "Multipart segment too short for superblock".into(),
                    ));
                }
                if multipart_part_size.is_none() {
                    return Err(AmberError::Invalid(
                        "Multipart segment is missing part-size policy in superblock".into(),
                    ));
                }
                (SUPERBLOCK_SIZE as u64, size - SUPERBLOCK_SIZE as u64)
            };

            segments.push(ArchiveSegment {
                path: segment_path.clone(),
                logical_start,
                logical_length,
                physical_header_length,
            });
            logical_start += logical_length;
            handles.push(handle);
        }

        Self::new(handles, segments)
    }

    pub fn segments(&self) -> &[ArchiveSegment] {
        &self.segments
    }

    pub fn logical_size(&self) -> u64 {
        self.segments.last().map_or(0, ArchiveSegment::logical_end)
    }

    pub fn sync(&mut self) -> std::io::Result<()> {
        for handle in &mut self.handles {
            handle.sync_data()?;
        }
        Ok(())
    }

    fn segment_index_for_offset(&self, offset: u64) -> Option<usize> {
        self.segments
            .iter()
            .position(|segment| segment.logical_start <= offset && offset < segment.logical_end())
    }
}

impl Read for LogicalArchiveReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.pos >= self.logical_size() {
            return Ok(0);
        }
        let mut remaining = buf.len().min((self.logical_size() - self.pos) as usize);
        let mut written = 0usize;
        while remaining > 0 {
            let Some(index) = self.segment_index_for_offset(self.pos) else {
                break;
            };
            let segment = &self.segments[index];
            let handle = &mut self.handles[index];
            let available = (segment.logical_end() - self.pos) as usize;
            let chunk_size = remaining.min(available);
            let physical = segment
                .logical_to_physical(self.pos)
                .map_err(to_io_invalid)?;
            handle.seek(SeekFrom::Start(physical))?;
            let read_len = handle.read(&mut buf[written..written + chunk_size])?;
            self.pos += read_len as u64;
            written += read_len;
            remaining -= read_len;
            if read_len != chunk_size {
                break;
            }
        }
        Ok(written)
    }
}

impl Seek for LogicalArchiveReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i128,
            SeekFrom::Current(offset) => self.pos as i128 + offset as i128,
            SeekFrom::End(offset) => self.logical_size() as i128 + offset as i128,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "negative seek position",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

impl Write for LogicalArchiveReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut remaining = buf.len();
        let mut written_total = 0usize;
        let mut data_pos = 0usize;
        while remaining > 0 {
            let Some(index) = self.segment_index_for_offset(self.pos) else {
                return Err(std::io::Error::other(
                    "write offset outside logical archive",
                ));
            };
            let segment = &self.segments[index];
            let handle = &mut self.handles[index];
            let available = (segment.logical_end() - self.pos) as usize;
            let chunk_size = remaining.min(available);
            let physical = segment
                .logical_to_physical(self.pos)
                .map_err(to_io_invalid)?;
            handle.seek(SeekFrom::Start(physical))?;
            let written = handle.write(&buf[data_pos..data_pos + chunk_size])?;
            if written != chunk_size {
                return Err(std::io::Error::other("short write while updating archive"));
            }
            self.pos += written as u64;
            written_total += written;
            data_pos += written;
            remaining -= written;
        }
        Ok(written_total)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        for handle in &mut self.handles {
            handle.flush()?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct LogicalArchiveWriter {
    base_path: PathBuf,
    part_size: Option<u64>,
    segment_header_bytes: Vec<u8>,
    handles: Vec<File>,
    segments: Vec<ArchiveSegment>,
    segment_paths: Vec<PathBuf>,
    current_segment_index: usize,
    logical_pos: u64,
}

impl LogicalArchiveWriter {
    pub fn new(base_path: &Path, part_size: Option<u64>) -> AmberResult<Self> {
        if let Some(part_size) = part_size
            && part_size == 0
        {
            return Err(AmberError::Invalid("part_size must be positive".into()));
        }
        let mut writer = Self {
            base_path: base_path.to_path_buf(),
            part_size,
            segment_header_bytes: Vec::new(),
            handles: Vec::new(),
            segments: Vec::new(),
            segment_paths: Vec::new(),
            current_segment_index: 0,
            logical_pos: 0,
        };
        writer.open_next_segment()?;
        Ok(writer)
    }

    pub fn logical_size(&self) -> u64 {
        self.logical_pos
    }

    pub fn segments(&self) -> &[ArchiveSegment] {
        &self.segments
    }

    pub fn part_size(&self) -> Option<u64> {
        self.part_size
    }

    pub fn repeated_segment_header_length(&self) -> u64 {
        if self.part_size.is_some() {
            self.segment_header_bytes.len() as u64
        } else {
            0
        }
    }

    pub fn segment_paths(&self) -> &[PathBuf] {
        &self.segment_paths
    }

    pub fn set_segment_header_bytes(&mut self, header: &[u8]) -> AmberResult<()> {
        if self.logical_pos != header.len() as u64 {
            return Err(AmberError::Invalid(
                "segment header bytes must be set immediately after writing the primary superblock"
                    .into(),
            ));
        }
        self.segment_header_bytes = header.to_vec();
        Ok(())
    }

    fn open_next_segment(&mut self) -> AmberResult<()> {
        let segment_index = self.handles.len() as u32 + 1;
        let path = if self.part_size.is_some() {
            multipart_segment_path(&self.base_path, segment_index)?
        } else {
            self.base_path.clone()
        };
        let mut handle = File::create(&path)?;
        let mut physical_header_length = 0u64;
        if segment_index > 1 {
            if self.segment_header_bytes.is_empty() {
                return Err(AmberError::Invalid(
                    "multipart rollover requires configured segment header bytes".into(),
                ));
            }
            handle.write_all(&self.segment_header_bytes)?;
            physical_header_length = self.segment_header_bytes.len() as u64;
        }
        self.handles.push(handle);
        self.segment_paths.push(path.clone());
        self.segments.push(ArchiveSegment {
            path,
            logical_start: self.logical_pos,
            logical_length: 0,
            physical_header_length,
        });
        self.current_segment_index = self.handles.len() - 1;
        Ok(())
    }
}

impl Seek for LogicalArchiveWriter {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(offset) if offset == self.logical_pos => Ok(self.logical_pos),
            SeekFrom::Current(0) => Ok(self.logical_pos),
            _ => Err(std::io::Error::other(
                "LogicalArchiveWriter only supports appending sequential writes",
            )),
        }
    }
}

impl Write for LogicalArchiveWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = &mut self.handles[self.current_segment_index];
        let written = handle.write(buf)?;
        if written != buf.len() {
            return Err(std::io::Error::other("short write while writing archive"));
        }
        self.logical_pos += written as u64;
        let current = &mut self.segments[self.current_segment_index];
        current.logical_length += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(handle) = self.handles.get_mut(self.current_segment_index) {
            handle.flush()?;
        }
        Ok(())
    }
}

impl RecordWriteTarget for LogicalArchiveWriter {
    fn reserve_contiguous(&mut self, length: u64) -> AmberResult<()> {
        if let Some(part_size) = self.part_size {
            let current = &self.segments[self.current_segment_index];
            let current_physical = current.physical_length();
            let hidden_header = if self.current_segment_index > 0 {
                self.segment_header_bytes.len() as u64
            } else {
                0
            };
            let max_record_bytes = part_size - hidden_header;
            if length > max_record_bytes {
                return Err(AmberError::Invalid(
                    "record exceeds configured multipart segment size".into(),
                ));
            }
            if current.logical_length > 0 && current_physical + length > part_size {
                self.open_next_segment()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct LogicalArchiveAppender {
    archive_path: PathBuf,
    part_size: Option<u64>,
    segment_header_bytes: Vec<u8>,
    handles: Vec<File>,
    segments: Vec<ArchiveSegment>,
    current_segment_index: usize,
    logical_pos: u64,
}

impl LogicalArchiveAppender {
    pub fn open_path(path: &Path) -> AmberResult<Self> {
        let segment_paths = discover_archive_segment_paths(path)?;
        let mut handles = Vec::new();
        let mut segments = Vec::new();
        let mut segment_header_bytes = Vec::new();
        let mut logical_start = 0u64;
        let mut archive_uuid = None;
        let mut multipart_part_size = None;

        for (idx, segment_path) in segment_paths.iter().enumerate() {
            let handle = OpenOptions::new().append(true).open(segment_path)?;
            let size = handle.metadata()?.len();
            let mut header_fh = File::open(segment_path)?;
            let mut superblock_bytes = vec![0u8; SUPERBLOCK_SIZE];
            header_fh.read_exact(&mut superblock_bytes)?;
            let superblock = read_superblock(&mut header_fh)?;
            match archive_uuid {
                None => {
                    archive_uuid = Some(superblock.uuid);
                    segment_header_bytes = superblock_bytes;
                    multipart_part_size = match superblock.multipart_part_size {
                        0 => None,
                        value => Some(value),
                    };
                }
                Some(uuid) if uuid != superblock.uuid => {
                    return Err(AmberError::Invalid(
                        "Multipart segment archive UUID mismatch".into(),
                    ));
                }
                Some(_) if superblock.multipart_part_size != multipart_part_size.unwrap_or(0) => {
                    return Err(AmberError::Invalid(
                        "Multipart segment part-size policy mismatch".into(),
                    ));
                }
                _ => {}
            }

            let (physical_header_length, logical_length) = if idx == 0 {
                (0u64, size)
            } else {
                if size < SUPERBLOCK_SIZE as u64 {
                    return Err(AmberError::Invalid(
                        "Multipart segment too short for superblock".into(),
                    ));
                }
                if multipart_part_size.is_none() {
                    return Err(AmberError::Invalid(
                        "Multipart segment is missing part-size policy in superblock".into(),
                    ));
                }
                (SUPERBLOCK_SIZE as u64, size - SUPERBLOCK_SIZE as u64)
            };
            segments.push(ArchiveSegment {
                path: segment_path.clone(),
                logical_start: logical_start,
                logical_length,
                physical_header_length,
            });
            logical_start += logical_length;
            handles.push(handle);
        }

        Ok(Self {
            archive_path: canonical_archive_base_path(path)?,
            part_size: if segments.len() > 1 {
                multipart_part_size
            } else {
                None
            },
            segment_header_bytes,
            current_segment_index: handles.len() - 1,
            logical_pos: segments.last().map_or(0, ArchiveSegment::logical_end),
            handles,
            segments,
        })
    }

    pub fn logical_size(&self) -> u64 {
        self.logical_pos
    }

    pub fn segments(&self) -> &[ArchiveSegment] {
        &self.segments
    }

    pub fn part_size(&self) -> Option<u64> {
        self.part_size
    }

    pub fn repeated_segment_header_length(&self) -> u64 {
        if self.part_size.is_some() {
            self.segment_header_bytes.len() as u64
        } else {
            0
        }
    }

    fn open_next_segment(&mut self) -> AmberResult<()> {
        let part_size = self.part_size.ok_or_else(|| {
            AmberError::Invalid("single-file archive cannot open a new segment".into())
        })?;
        let segment_index = self.handles.len() as u32 + 1;
        let path = multipart_segment_path(&self.archive_path, segment_index)?;
        let mut handle = File::create(&path)?;
        handle.write_all(&self.segment_header_bytes)?;
        self.handles.push(handle);
        self.segments.push(ArchiveSegment {
            path,
            logical_start: self.logical_pos,
            logical_length: 0,
            physical_header_length: self.segment_header_bytes.len() as u64,
        });
        self.current_segment_index = self.handles.len() - 1;
        self.part_size = Some(part_size);
        Ok(())
    }
}

impl Seek for LogicalArchiveAppender {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(offset) if offset == self.logical_pos => Ok(self.logical_pos),
            SeekFrom::Current(0) => Ok(self.logical_pos),
            _ => Err(std::io::Error::other(
                "LogicalArchiveAppender only supports appending sequential writes",
            )),
        }
    }
}

impl Write for LogicalArchiveAppender {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written_total = 0usize;
        let mut pos = 0usize;
        let mut remaining = buf.len();
        while remaining > 0 {
            let chunk_size = if let Some(part_size) = self.part_size {
                let current = &self.segments[self.current_segment_index];
                let available = part_size.saturating_sub(current.physical_length()) as usize;
                if available == 0 {
                    self.open_next_segment().map_err(to_io_invalid)?;
                    continue;
                }
                remaining.min(available)
            } else {
                remaining
            };
            let handle = &mut self.handles[self.current_segment_index];
            let written = handle.write(&buf[pos..pos + chunk_size])?;
            if written != chunk_size {
                return Err(std::io::Error::other("short write while appending archive"));
            }
            self.logical_pos += written as u64;
            written_total += written;
            pos += written;
            remaining -= written;
            self.segments[self.current_segment_index].logical_length += written as u64;
        }
        Ok(written_total)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        for handle in &mut self.handles {
            handle.flush()?;
        }
        Ok(())
    }
}

impl RecordWriteTarget for LogicalArchiveAppender {
    fn reserve_contiguous(&mut self, length: u64) -> AmberResult<()> {
        if let Some(part_size) = self.part_size {
            let current = &self.segments[self.current_segment_index];
            let current_physical = current.physical_length();
            let hidden_header = if self.current_segment_index > 0 {
                self.segment_header_bytes.len() as u64
            } else {
                0
            };
            let max_record_bytes = part_size - hidden_header;
            if length > max_record_bytes {
                return Err(AmberError::Invalid(
                    "record exceeds configured multipart segment size".into(),
                ));
            }
            if current.logical_length > 0 && current_physical + length > part_size {
                self.open_next_segment()?;
            }
        }
        Ok(())
    }
}

pub fn copy_archive_set(src_path: &Path, dst_path: &Path) -> AmberResult<Vec<PathBuf>> {
    let src_segments = discover_archive_segment_paths(src_path)?;
    if src_segments.len() == 1 {
        assert_archive_output_path_clear(dst_path, false)?;
        fs::copy(&src_segments[0], dst_path)?;
        return Ok(vec![dst_path.to_path_buf()]);
    }
    assert_archive_output_path_clear(dst_path, true)?;
    let mut copied = Vec::new();
    for (index, src_segment) in src_segments.iter().enumerate() {
        let dst_segment = multipart_segment_path(dst_path, index as u32 + 1)?;
        fs::copy(src_segment, &dst_segment)?;
        copied.push(dst_segment);
    }
    Ok(copied)
}

fn to_io_invalid(err: AmberError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
}

#[cfg(test)]
#[path = "tests/archiveio.rs"]
mod tests;
