use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::archiveio::LogicalArchiveReader;
use crate::constants::CODEC_NONE;
use crate::corrupt::{corrupt_chunk_window, corrupt_random_chunks};
use crate::reader::ArchiveReader;
use crate::repair::detect_corrupted_symbols;
use crate::writer::ArchiveWriter;

fn tempdir() -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!(
        "amber-rust-corrupt-test-{stamp}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn corrupt_random_chunks_flips_selected_data_chunks() {
    let tmp = tempdir();
    let archive = tmp.join("sample.amber");
    let data = tmp.join("data.bin");
    fs::write(&data, vec![b'A'; 65_536 * 3]).unwrap();
    let mut writer =
        ArchiveWriter::new(&archive, None, None, None, None, None, None, None, None, Some(0))
            .unwrap();
    writer.open().unwrap();
    writer
        .add_file("data.bin", &data, Some(CODEC_NONE), Some(65_536), None)
        .unwrap();
    writer.finalize().unwrap();
    writer.close();

    corrupt_random_chunks(&archive, 2, Some(7), 10, false, None, None).unwrap();

    let mut reader = ArchiveReader::new(&archive);
    reader.open().unwrap();
    let mut fh = LogicalArchiveReader::open_path(&archive).unwrap();
    let corrupted = detect_corrupted_symbols(&reader, &mut fh).unwrap();
    assert_eq!(corrupted.len(), 2);

    let _ = fs::remove_dir_all(tmp);
}

#[test]
fn corrupt_chunk_window_flips_contiguous_chunks() {
    let tmp = tempdir();
    let archive = tmp.join("sample.amber");
    let data = tmp.join("data.bin");
    fs::write(&data, vec![b'B'; 65_536 * 4]).unwrap();
    let mut writer =
        ArchiveWriter::new(&archive, None, None, None, None, None, None, None, None, Some(0))
            .unwrap();
    writer.open().unwrap();
    writer
        .add_file("data.bin", &data, Some(CODEC_NONE), Some(65_536), None)
        .unwrap();
    writer.finalize().unwrap();
    writer.close();

    corrupt_chunk_window(&archive, 1, 2, 10, false, None, None).unwrap();

    let mut reader = ArchiveReader::new(&archive);
    reader.open().unwrap();
    let mut fh = LogicalArchiveReader::open_path(&archive).unwrap();
    let corrupted = detect_corrupted_symbols(&reader, &mut fh)
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(corrupted, vec![1, 2]);

    let _ = fs::remove_dir_all(tmp);
}

#[test]
fn corrupt_random_chunks_supports_multipart_archive() {
    let tmp = tempdir();
    let archive = tmp.join("sample.amber");
    let data = tmp.join("data.bin");
    fs::write(&data, vec![b'D'; 65_536 * 8]).unwrap();
    let mut writer = ArchiveWriter::new(
        &archive,
        None,
        None,
        None,
        None,
        Some(120_000),
        None,
        None,
        None,
        Some(0),
    )
    .unwrap();
    writer.open().unwrap();
    writer
        .add_file("data.bin", &data, Some(CODEC_NONE), Some(65_536), None)
        .unwrap();
    writer.finalize().unwrap();
    writer.close();

    let seg2 = std::path::PathBuf::from(format!("{}.002", archive.display()));
    corrupt_random_chunks(&seg2, 2, Some(5), 10, false, None, None).unwrap();

    let mut reader = ArchiveReader::new(&seg2);
    reader.open().unwrap();
    let mut fh = LogicalArchiveReader::open_path(&seg2).unwrap();
    let corrupted = detect_corrupted_symbols(&reader, &mut fh).unwrap();
    assert_eq!(corrupted.len(), 2);

    let _ = fs::remove_dir_all(tmp);
}
