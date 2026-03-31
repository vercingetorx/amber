    use std::fs;
    use std::io::{Seek, SeekFrom};
    use std::time::{SystemTime, UNIX_EPOCH};

    use filetime::{FileTime, set_file_times};

    use super::{ArchiveWriter, CANONICAL_WRITER_INFO};
    use crate::archiveio::LogicalArchiveReader;
    use crate::constants::{CODEC_ZSTD, RTYPE_ENTRY_BEGIN};
    use crate::records::read_record_at;
    use crate::reader::ArchiveReader;
    use crate::superblock::SUPERBLOCK_SIZE;
    use crate::tlv::{get_list, get_map, get_u64, iter_tlvs};

    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!(
            "amber-rust-writer-test-{stamp}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn writer_creates_plaintext_archive_reader_can_verify() {
        let tmp = tempdir();
        let input = tmp.join("hello.txt");
        fs::write(&input, b"hello from writer").unwrap();
        let archive = tmp.join("out.amber");

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_file("hello.txt", &input, None, Some(8), None)
            .unwrap();
        writer.finalize().unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert_eq!(reader.entries.len(), 1);
        let extracted = tmp.join("extracted.txt");
        let entry = reader.entries[0].clone();
        reader.extract(&entry, &extracted).unwrap();
        assert_eq!(fs::read(&extracted).unwrap(), b"hello from writer");
        assert!(!reader.symbols.is_empty());
        assert!(!reader.anchors_data.is_empty());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn writer_creates_encrypted_archive_reader_can_verify() {
        let tmp = tempdir();
        let input = tmp.join("secret.bin");
        fs::write(&input, b"top secret payload").unwrap();
        let archive = tmp.join("enc.amber");

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            Some("password"),
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_file("secret.bin", &input, None, Some(7), None)
            .unwrap();
        writer.finalize().unwrap();

        let mut reader =
            ArchiveReader::new_with_credentials(&archive, Some("password".into()), None);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn writer_creates_zstd_archive_reader_can_verify() {
        let tmp = tempdir();
        let input = tmp.join("zstd.bin");
        fs::write(&input, vec![0x33u8; 150_000]).unwrap();
        let archive = tmp.join("zstd.amber");

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(32_768),
            Some(CODEC_ZSTD),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_file("zstd.bin", &input, Some(CODEC_ZSTD), Some(32_768), None)
            .unwrap();
        writer.finalize().unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert_eq!(reader.entries.len(), 1);
        let extracted = tmp.join("zstd-out.bin");
        let entry = reader.entries[0].clone();
        reader.extract(&entry, &extracted).unwrap();
        assert_eq!(fs::read(&extracted).unwrap(), fs::read(&input).unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn writer_creates_multipart_archive_with_segments_index() {
        let tmp = tempdir();
        let input = tmp.join("big.bin");
        fs::write(&input, vec![0x5Au8; 120_000]).unwrap();
        let archive = tmp.join("multi.amber");

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(16_384),
            None,
            None,
            None,
            Some(70_000),
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_file("big.bin", &input, None, Some(16_384), None)
            .unwrap();
        writer.finalize().unwrap();

        assert!(archive.with_extension("amber.001").exists());
        assert!(archive.with_extension("amber.002").exists());

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert!(reader.segments_meta.len() >= 2);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn writer_preserves_explicit_zero_metadata_fields() {
        let tmp = tempdir();
        let archive = tmp.join("zero-meta.amber");

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_dir("zero", Some(0), Some(0), Some(0), Some(0), Some(0))
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut raw = LogicalArchiveReader::open_path(&archive).unwrap();
        raw.seek(SeekFrom::Start(SUPERBLOCK_SIZE as u64)).unwrap();
        let record = read_record_at(&mut raw, SUPERBLOCK_SIZE as u64, None).unwrap();
        assert_eq!(record.rtype, RTYPE_ENTRY_BEGIN);
        let tags = iter_tlvs(&record.payload)
            .unwrap()
            .into_iter()
            .map(|(tag, _)| tag)
            .collect::<Vec<_>>();
        assert!(tags.contains(&4));
        assert!(tags.contains(&5));
        assert!(tags.contains(&6));

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let index = reader.index.as_ref().unwrap();
        let entries = get_list(index, "entries").unwrap();
        let zero = entries
            .iter()
            .find(|entry| get_u64(entry, "kind") == Some(1))
            .unwrap();
        assert_eq!(get_u64(zero, "mode"), Some(0));
        assert_eq!(
            get_map(zero, "mtime").and_then(|mtime| get_u64(mtime, "sec")),
            Some(0)
        );
        assert_eq!(
            get_map(zero, "atime").and_then(|atime| get_u64(atime, "sec")),
            Some(0)
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn writer_treats_zero_chunk_size_as_default() {
        let tmp = tempdir();
        let archive = tmp.join("zero-chunk.amber");
        let input = tmp.join("payload.bin");
        fs::write(&input, vec![0x55u8; 32]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(4096),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_file("payload.bin", &input, None, Some(0), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let entry = reader
            .index
            .as_ref()
            .and_then(|index| get_list(index, "entries"))
            .and_then(|entries| entries.first())
            .unwrap();
        assert_eq!(get_u64(entry, "chunk_size"), Some(4096));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn writer_emits_zero_size_in_entry_begin_and_index() {
        let tmp = tempdir();
        let archive = tmp.join("zero-size.amber");
        let input = tmp.join("empty.bin");
        fs::write(&input, []).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer.add_file("empty.bin", &input, None, None, None).unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut raw = LogicalArchiveReader::open_path(&archive).unwrap();
        raw.seek(SeekFrom::Start(SUPERBLOCK_SIZE as u64)).unwrap();
        let record = read_record_at(&mut raw, SUPERBLOCK_SIZE as u64, None).unwrap();
        assert_eq!(record.rtype, RTYPE_ENTRY_BEGIN);
        let tags = iter_tlvs(&record.payload)
            .unwrap()
            .into_iter()
            .map(|(tag, _)| tag)
            .collect::<Vec<_>>();
        assert!(tags.contains(&7));

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let entry = reader
            .index
            .as_ref()
            .and_then(|index| get_list(index, "entries"))
            .and_then(|entries| entries.first())
            .unwrap();
        assert_eq!(get_u64(entry, "size"), Some(0));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn writer_preserves_file_nanosecond_timestamps_from_filesystem() {
        let tmp = tempdir();
        let archive = tmp.join("nsec.amber");
        let input = tmp.join("nsec.bin");
        fs::write(&input, b"nanoseconds").unwrap();
        set_file_times(
            &input,
            FileTime::from_unix_time(1_700_000_002, 123_456_789),
            FileTime::from_unix_time(1_700_000_001, 987_654_321),
        )
        .unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer.add_file("nsec.bin", &input, None, None, None).unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let entry = reader
            .entries
            .iter()
            .find(|entry| entry.path == "nsec.bin")
            .unwrap();
        assert_eq!(entry.atime_sec, Some(1_700_000_002));
        assert_eq!(entry.atime_nsec, Some(123_456_789));
        assert_eq!(entry.mtime_sec, Some(1_700_000_001));
        assert_eq!(entry.mtime_nsec, Some(987_654_321));

        let index_entry = reader
            .index
            .as_ref()
            .and_then(|index| get_list(index, "entries"))
            .and_then(|entries| entries.iter().find(|entry| get_u64(entry, "kind") == Some(0)))
            .unwrap();
        assert_eq!(
            get_map(index_entry, "atime").and_then(|atime| get_u64(atime, "sec")),
            Some(1_700_000_002)
        );
        assert_eq!(
            get_map(index_entry, "atime").and_then(|atime| get_u64(atime, "nsec")),
            Some(123_456_789)
        );
        assert_eq!(
            get_map(index_entry, "mtime").and_then(|mtime| get_u64(mtime, "sec")),
            Some(1_700_000_001)
        );
        assert_eq!(
            get_map(index_entry, "mtime").and_then(|mtime| get_u64(mtime, "nsec")),
            Some(987_654_321)
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn writer_uses_canonical_writer_info() {
        let tmp = tempdir();
        let input = tmp.join("hello.txt");
        let archive = tmp.join("writer-info.amber");
        fs::write(&input, b"hello").unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer.add_file("hello.txt", &input, None, None, None).unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let writer_info = reader
            .index
            .as_ref()
            .and_then(|index| crate::tlv::get_string(index, "writer_info"));
        assert_eq!(writer_info, Some(CANONICAL_WRITER_INFO));

        let _ = fs::remove_dir_all(tmp);
    }
