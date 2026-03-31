    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::rebuild_index;
    use crate::append::append_to_archive;
    use crate::LogicalArchiveReader;
    use crate::records::RECORD_HEADER_SIZE;
    use crate::reader::ArchiveReader;
    use crate::repair::repair_archive;
    use crate::tlv::get_string;
    use crate::writer::{ArchiveWriter, CANONICAL_WRITER_INFO};

    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!(
            "amber-rust-recover-test-{stamp}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn create_sample_files(base: &std::path::Path) {
        let docs = base.join("docs");
        fs::create_dir_all(&docs).unwrap();
        fs::write(docs.join("a.txt"), b"hello world\nhello world\n").unwrap();
        fs::write(docs.join("b.bin"), vec![0x44u8; 4096]).unwrap();
        fs::write(base.join("notes.md"), b"# Title\nSome content\n").unwrap();
    }

    fn build_sample_archive(base: &std::path::Path, password: Option<&str>) -> std::path::PathBuf {
        let archive = base.join("sample.amber");
        create_sample_files(base);
        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            password,
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
            .add_dir("docs", None, None, None, None, None)
            .unwrap();
        writer
            .add_file("docs/a.txt", &base.join("docs/a.txt"), None, None, None)
            .unwrap();
        writer
            .add_file("docs/b.bin", &base.join("docs/b.bin"), None, None, None)
            .unwrap();
        writer
            .add_file("notes.md", &base.join("notes.md"), None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();
        archive
    }

    fn create_deterministic_noise_file(path: &std::path::Path, size: usize, seed: u64) {
        let mut state = seed;
        let mut out = std::fs::File::create(path).unwrap();
        let mut remaining = size;
        while remaining > 0 {
            let piece_len = remaining.min(65_536);
            let mut piece = vec![0u8; piece_len];
            for byte in &mut piece {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = (state >> 56) as u8;
            }
            out.write_all(&piece).unwrap();
            remaining -= piece_len;
        }
    }

    fn build_chunk_repair_archive(base: &std::path::Path) -> std::path::PathBuf {
        let archive = base.join("chunk-repair.amber");
        let specs = [
            ("big-a.bin", 3 * 1024 * 1024usize, 11u64),
            ("big-b.bin", 2 * 1024 * 1024usize, 29u64),
            ("big-c.bin", 1 * 1024 * 1024usize, 47u64),
        ];
        for (name, size, seed) in specs {
            create_deterministic_noise_file(&base.join(name), size, seed);
        }
        let mut writer = ArchiveWriter::new(
            &archive, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();
        writer.open().unwrap();
        for (name, _size, _seed) in specs {
            writer.add_file(name, &base.join(name), None, None, None).unwrap();
        }
        writer.finalize().unwrap();
        writer.close();
        archive
    }

    fn build_chunk_repair_archive_encrypted(
        base: &std::path::Path,
        password: &str,
    ) -> std::path::PathBuf {
        let archive = base.join("chunk-repair-encrypted.amber");
        let specs = [
            ("enc-a.bin", 3 * 1024 * 1024usize, 53u64),
            ("enc-b.bin", 2 * 1024 * 1024usize, 59u64),
            ("enc-c.bin", 1 * 1024 * 1024usize, 61u64),
        ];
        for (name, size, seed) in specs {
            create_deterministic_noise_file(&base.join(name), size, seed);
        }
        let mut writer =
            ArchiveWriter::new(&archive, None, None, Some(password), None, None, None, None, None, None)
                .unwrap();
        writer.open().unwrap();
        for (name, _size, _seed) in specs {
            writer
                .add_file(name, &base.join(name), None, None, None)
                .unwrap();
        }
        writer.finalize().unwrap();
        writer.close();
        archive
    }

    fn build_anchor_archive(base: &std::path::Path, name: &str, size: usize) -> std::path::PathBuf {
        let archive = base.join(name);
        let big = base.join("big.bin");
        create_deterministic_noise_file(&big, size, 0xBAD5EED);
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
            Some(4096),
        )
        .unwrap();
        writer.open().unwrap();
        writer.add_file("f.bin", &big, None, None, None).unwrap();
        writer.finalize().unwrap();
        writer.close();
        archive
    }

    #[test]
    fn rebuild_index_recovers_from_broken_trailer() {
        let tmp = tempdir();
        let input = tmp.join("payload.bin");
        let archive = tmp.join("recover.amber");
        fs::write(&input, vec![0x51u8; 100_000]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(16_384),
            None,
            None,
            None,
            None,
            Some(20_000),
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_file("payload.bin", &input, None, Some(16_384), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        let len = raw.metadata().unwrap().len();
        raw.seek(SeekFrom::Start(len - 96)).unwrap();
        raw.write_all(&vec![0u8; 96]).unwrap();
        drop(raw);

        let mut broken = ArchiveReader::new(&archive);
        assert!(broken.open().is_err());

        let parity_count = rebuild_index(&archive, None, None).unwrap();
        assert!(parity_count > 0);

        let mut rebuilt = ArchiveReader::new(&archive);
        rebuilt.open().unwrap();
        assert!(rebuilt.verify().unwrap());
        assert_eq!(
            rebuilt
                .index
                .as_ref()
                .and_then(|index| get_string(index, "writer_info")),
            Some(CANONICAL_WRITER_INFO)
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rebuild_index_detects_missing_chunks() {
        let tmp = tempdir();
        let archive = build_sample_archive(&tmp, None);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let file_entry = reader
            .list()
            .iter()
            .find(|entry| entry.kind == 0 && entry.path == "docs/a.txt")
            .unwrap()
            .clone();
        assert!(!file_entry.chunks.is_empty());
        let chunk_offset = file_entry.chunks[0].offset;
        drop(reader);

        let mut raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        raw.seek(SeekFrom::Start(chunk_offset)).unwrap();
        let mut header = [0u8; RECORD_HEADER_SIZE];
        raw.read_exact(&mut header).unwrap();
        header[0] ^= 0xFF;
        raw.seek(SeekFrom::Start(chunk_offset)).unwrap();
        raw.write_all(&header).unwrap();
        drop(raw);

        let err = rebuild_index(&archive, None, None).unwrap_err();
        assert!(err.to_string().contains("missing chunk"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rebuild_preserves_good_anchors() {
        let tmp = tempdir();
        let archive = build_anchor_archive(&tmp, "anchors-good.amber", 3 * 1024 * 1024);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let orig = reader
            .anchors_meta
            .iter()
            .filter_map(|meta| crate::tlv::get_u64(meta, "offset"))
            .collect::<Vec<_>>();
        assert!(orig.len() >= 2);
        drop(reader);

        rebuild_index(&archive, None, None).unwrap();

        let mut rebuilt = ArchiveReader::new(&archive);
        rebuilt.open().unwrap();
        let rebuilt_offsets = rebuilt
            .index
            .as_ref()
            .and_then(|idx| crate::tlv::get_list(idx, "anchors"))
            .into_iter()
            .flat_map(|anchors| anchors.iter())
            .filter_map(|meta| crate::tlv::get_u64(meta, "offset"))
            .collect::<Vec<_>>();
        assert_eq!(
            rebuilt_offsets.iter().copied().collect::<std::collections::BTreeSet<_>>(),
            orig.iter().copied().collect::<std::collections::BTreeSet<_>>()
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rebuild_drops_bad_anchor_keeps_good() {
        let tmp = tempdir();
        let archive = build_anchor_archive(&tmp, "anchors-bad.amber", 2 * 1024 * 1024);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let offsets = reader
            .anchors_meta
            .iter()
            .filter_map(|meta| crate::tlv::get_u64(meta, "offset"))
            .collect::<Vec<_>>();
        assert!(offsets.len() >= 2);
        drop(reader);

        let mut raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        raw.seek(SeekFrom::Start(offsets[0])).unwrap();
        let mut fixed = [0u8; RECORD_HEADER_SIZE];
        raw.read_exact(&mut fixed).unwrap();
        let header_len = u16::from_le_bytes([fixed[6], fixed[7]]) as u64;
        let flip_at = offsets[0] + RECORD_HEADER_SIZE as u64 + header_len + 8;
        raw.seek(SeekFrom::Start(flip_at)).unwrap();
        let mut byte = [0u8; 1];
        raw.read_exact(&mut byte).unwrap();
        raw.seek(SeekFrom::Start(flip_at)).unwrap();
        raw.write_all(&[byte[0] ^ 0xFF]).unwrap();
        drop(raw);

        rebuild_index(&archive, None, None).unwrap();

        let mut rebuilt = ArchiveReader::new(&archive);
        rebuilt.open().unwrap();
        let rebuilt_offsets = rebuilt
            .index
            .as_ref()
            .and_then(|idx| crate::tlv::get_list(idx, "anchors"))
            .into_iter()
            .flat_map(|anchors| anchors.iter())
            .filter_map(|meta| crate::tlv::get_u64(meta, "offset"))
            .collect::<Vec<_>>();
        assert!(!rebuilt_offsets.contains(&offsets[0]));
        assert_eq!(
            rebuilt_offsets.iter().copied().collect::<std::collections::BTreeSet<_>>(),
            offsets[1..]
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn append_references_tail_anchor_only() {
        let tmp = tempdir();
        let archive = build_anchor_archive(&tmp, "anchors-append.amber", 2 * 1024 * 1024);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.anchors_meta.len() >= 2);
        drop(reader);

        let appended = tmp.join("s.txt");
        fs::write(&appended, "hello").unwrap();
        append_to_archive(&archive, &[&appended], None, None).unwrap();

        let mut rebuilt = ArchiveReader::new(&archive);
        rebuilt.open().unwrap();
        let anchor_count = rebuilt
            .index
            .as_ref()
            .and_then(|idx| crate::tlv::get_list(idx, "anchors"))
            .map_or(0, |anchors| anchors.len());
        assert_eq!(anchor_count, 1);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn repair_archive_rebuilds_index_when_trailer_is_broken() {
        let tmp = tempdir();
        let input = tmp.join("payload.bin");
        let archive = tmp.join("repair-recover.amber");
        fs::write(&input, vec![0x61u8; 220_000]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(32_768),
            None,
            None,
            None,
            None,
            Some(2_000_000),
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_file("payload.bin", &input, None, Some(32_768), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let target_symbol = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity)
            .unwrap()
            .clone();
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(target_symbol.offset)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        let mut raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        let len = raw.metadata().unwrap().len();
        raw.seek(SeekFrom::Start(len - 96)).unwrap();
        raw.write_all(&vec![0u8; 96]).unwrap();
        drop(raw);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert!(result.output_path.is_some());
        assert_eq!(result.remaining_data_chunks, 0);

        let mut repaired = ArchiveReader::new(&archive);
        repaired.open().unwrap();
        assert!(repaired.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rebuild_then_repair_tolerates_corrupted_parity_record() {
        let tmp = tempdir();
        let archive = build_chunk_repair_archive(&tmp);
        crate::harden::append_amcf_parity(&archive, 200_000, None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let data_symbol = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity)
            .unwrap()
            .clone();
        let parity_symbol = reader
            .symbols
            .iter()
            .find(|sym| sym.is_parity)
            .unwrap()
            .clone();
        let trunc = reader.index_region_start;
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(data_symbol.offset)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.seek(SeekFrom::Start(parity_symbol.offset)).unwrap();
        rw.write_all(&[0x7E]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        let raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        raw.set_len(trunc).unwrap();
        drop(raw);

        let rebuild_count = rebuild_index(&archive, None, None).unwrap();
        assert!(rebuild_count > 0);
        let result = repair_archive(&archive, None, None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let remaining_data = result
            .remaining_corrupted
            .iter()
            .filter(|idx| !reader.symbols[**idx as usize].is_parity)
            .copied()
            .collect::<Vec<_>>();
        assert!(remaining_data.is_empty());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn repair_after_tail_truncate_and_no_anchors_succeeds() {
        let tmp = tempdir();
        let archive = build_sample_archive(&tmp, None);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(!reader.anchors_meta.is_empty());
        let first_anchor_off = reader
            .anchors_meta
            .iter()
            .filter_map(|meta| crate::tlv::get_u64(meta, "offset"))
            .min()
            .unwrap();
        drop(reader);

        let raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        raw.set_len(first_anchor_off).unwrap();
        drop(raw);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert_eq!(result.remaining_data_chunks, 0);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn missing_anchors_preserves_amcf_metadata_after_rebuild() {
        let tmp = tempdir();
        let archive = build_sample_archive(&tmp, None);
        crate::harden::append_amcf_parity(&archive, 200_000, None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let first_anchor_off = reader
            .anchors_meta
            .iter()
            .filter_map(|meta| crate::tlv::get_u64(meta, "offset"))
            .min()
            .unwrap();
        drop(reader);

        let raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        raw.set_len(first_anchor_off).unwrap();
        drop(raw);

        let rebuild_count = rebuild_index(&archive, None, None).unwrap();
        assert!(rebuild_count > 0);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(!reader.amcf_parities.is_empty());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn auto_rebuild_after_tail_truncate_plain_and_encrypted() {
        let tmp = tempdir();

        let plain_dir = tmp.join("plain");
        fs::create_dir_all(&plain_dir).unwrap();
        let plain_archive = build_sample_archive(&plain_dir, None);
        let mut reader = ArchiveReader::new(&plain_archive);
        reader.open().unwrap();
        let target = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity)
            .unwrap()
            .clone();
        let trunc = reader.index_region_start;
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&plain_archive).unwrap();
        rw.seek(SeekFrom::Start(target.offset)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);
        let raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&plain_archive)
            .unwrap();
        raw.set_len(trunc).unwrap();
        drop(raw);

        let plain_result = repair_archive(&plain_archive, None, None, None).unwrap();
        assert_eq!(plain_result.remaining_data_chunks, 0);
        let mut reader = ArchiveReader::new(&plain_archive);
        reader.open().unwrap();
        let mut raw = fs::File::open(&plain_archive).unwrap();
        raw.seek(SeekFrom::Start(reader.index_frame_offset))
            .unwrap();
        let mut magic = [0u8; 8];
        raw.read_exact(&mut magic).unwrap();
        assert_eq!(magic, crate::constants::INDEX_FRAME_MAGIC);
        assert!(reader.verify().unwrap());

        let enc_dir = tmp.join("enc");
        fs::create_dir_all(&enc_dir).unwrap();
        let encrypted_archive = build_sample_archive(&enc_dir, Some("secret"));
        let mut reader =
            ArchiveReader::new_with_credentials(&encrypted_archive, Some("secret".into()), None);
        reader.open().unwrap();
        let target = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity)
            .unwrap()
            .clone();
        let trunc = reader.index_region_start;
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&encrypted_archive).unwrap();
        rw.seek(SeekFrom::Start(target.offset)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);
        let raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&encrypted_archive)
            .unwrap();
        raw.set_len(trunc).unwrap();
        drop(raw);

        let enc_result = repair_archive(&encrypted_archive, Some("secret"), None, None).unwrap();
        assert_eq!(enc_result.remaining_data_chunks, 0);
        let mut reader =
            ArchiveReader::new_with_credentials(&encrypted_archive, Some("secret".into()), None);
        reader.open().unwrap();
        let mut raw = fs::File::open(&encrypted_archive).unwrap();
        raw.seek(SeekFrom::Start(reader.index_frame_offset))
            .unwrap();
        let mut bytes = [0u8; 8];
        raw.read_exact(&mut bytes).unwrap();
        assert_ne!(bytes, crate::constants::INDEX_FRAME_MAGIC);
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn encrypted_rebuild_then_repair_chunk_corruption() {
        let tmp = tempdir();
        let archive = build_chunk_repair_archive_encrypted(&tmp, "secret");

        crate::corrupt::corrupt_random_chunks(&archive, 1, Some(19), 0, false, Some("secret"), None)
            .unwrap();

        let mut reader = ArchiveReader::new_with_credentials(&archive, Some("secret".into()), None);
        reader.open().unwrap();
        let trunc = reader.index_region_start;
        drop(reader);

        let raw = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        raw.set_len(trunc).unwrap();
        drop(raw);

        repair_archive(&archive, Some("secret"), None, None).unwrap();

        let mut reader = ArchiveReader::new_with_credentials(&archive, Some("secret".into()), None);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }
