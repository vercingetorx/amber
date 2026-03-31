    use std::io::{Read, Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::records::{read_record_at, write_record};
    use crate::superblock::pack_superblock;

    use super::*;

    fn tempdir() -> PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!("amber-rust-test-{stamp}-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn discover_rejects_ambiguous_single_file_and_multipart_namespace() {
        let tmp = tempdir();
        let base = tmp.join("archive.amber");
        fs::write(&base, b"single").unwrap();
        fs::write(base.with_extension("amber.001"), b"one").unwrap();

        let err = discover_archive_segment_paths(&base).unwrap_err();
        assert!(err.to_string().contains("ambiguous archive path"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn discover_rejects_multipart_segment_gap() {
        let tmp = tempdir();
        let base = tmp.join("archive.amber");
        fs::write(base.with_extension("amber.001"), b"x").unwrap();
        fs::write(base.with_extension("amber.003"), b"x").unwrap();

        let err = discover_archive_segment_paths(&base).unwrap_err();
        assert!(err.to_string().contains("multipart segment gap detected"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn discover_relative_single_file_archive_from_cwd() {
        let tmp = tempdir();
        let cwd = std::env::current_dir().unwrap();
        let archive = tmp.join("test.amber");
        fs::write(&archive, b"amber").unwrap();

        std::env::set_current_dir(&tmp).unwrap();
        let discovered = discover_archive_segment_paths(std::path::Path::new("test.amber")).unwrap();
        std::env::set_current_dir(cwd).unwrap();

        assert_eq!(discovered, vec![std::path::PathBuf::from("test.amber")]);
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn assert_output_path_clear_rejects_existing_namespace_member() {
        let tmp = tempdir();
        let base = tmp.join("archive.amber");
        fs::write(base.with_extension("amber.003"), b"x").unwrap();

        assert!(assert_archive_output_path_clear(&base, true).is_err());
        assert!(assert_archive_output_path_clear(&base, false).is_err());
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn single_file_logical_reader_matches_raw_bytes() {
        let tmp = tempdir();
        let path = tmp.join("sample.amber");
        fs::write(&path, b"abcdef").unwrap();
        let mut reader = LogicalArchiveReader::open_single(&path).unwrap();
        let mut out = [0u8; 2];
        assert_eq!(reader.logical_size(), 6);
        reader.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"ab");
        reader.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"cd");
        assert_eq!(reader.seek(SeekFrom::End(-2)).unwrap(), 4);
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, b"ef");
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn logical_reader_skips_repeated_segment_superblocks() {
        let tmp = tempdir();
        let archive_uuid = [0x11; 16];
        let seg1 = tmp.join("archive.amber.001");
        let seg2 = tmp.join("archive.amber.002");
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, Some(120_000), None);

        let payload1 = vec![b'A'; 48];
        let payload2 = vec![b'B'; 32];
        {
            let mut fh = File::create(&seg1).unwrap();
            fh.write_all(&superblock).unwrap();
            fh.write_all(&payload1).unwrap();
        }
        {
            let mut fh = File::create(&seg2).unwrap();
            fh.write_all(&superblock).unwrap();
            fh.write_all(&payload2).unwrap();
        }

        let mut reader = LogicalArchiveReader::open_path(&seg1).unwrap();
        assert_eq!(
            reader.logical_size(),
            superblock.len() as u64 + payload1.len() as u64 + payload2.len() as u64
        );
        let mut sb_out = vec![0u8; superblock.len()];
        reader.read_exact(&mut sb_out).unwrap();
        assert_eq!(sb_out, superblock);
        let mut p1 = vec![0u8; payload1.len()];
        reader.read_exact(&mut p1).unwrap();
        assert_eq!(p1, payload1);
        let mut p2 = vec![0u8; payload2.len()];
        reader.read_exact(&mut p2).unwrap();
        assert_eq!(p2, payload2);
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn record_reads_cross_segment_boundary_with_hidden_segment_header() {
        let tmp = tempdir();
        let archive_uuid = [0x22; 16];
        let seg1 = tmp.join("archive.amber.001");
        let seg2 = tmp.join("archive.amber.002");
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, Some(120_000), None);

        let part1_path = tmp.join("part1.bin");
        let part2_path = tmp.join("part2.bin");
        let (off1, _, _) = {
            let mut fh = File::create(&part1_path).unwrap();
            write_record(&mut fh, 1, 0, b"", &[b'A'; 20], None).unwrap()
        };
        let (off2, _, _) = {
            let mut fh = File::create(&part2_path).unwrap();
            write_record(&mut fh, 2, 0, b"", &[b'B'; 20], None).unwrap()
        };
        let raw1 = fs::read(&part1_path).unwrap();
        let raw2 = fs::read(&part2_path).unwrap();

        {
            let mut fh = File::create(&seg1).unwrap();
            fh.write_all(&superblock).unwrap();
            fh.write_all(&raw1).unwrap();
        }
        {
            let mut fh = File::create(&seg2).unwrap();
            fh.write_all(&superblock).unwrap();
            fh.write_all(&raw2).unwrap();
        }

        let mut reader = LogicalArchiveReader::open_path(&seg1).unwrap();
        let r1 = read_record_at(&mut reader, superblock.len() as u64 + off1, None).unwrap();
        let r2 = read_record_at(
            &mut reader,
            superblock.len() as u64 + raw1.len() as u64 + off2,
            None,
        )
        .unwrap();
        assert_eq!(r1.rtype, 1);
        assert_eq!(r1.payload, vec![b'A'; 20]);
        assert_eq!(r2.rtype, 2);
        assert_eq!(r2.payload, vec![b'B'; 20]);
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn logical_reader_open_path_rw_writes_past_hidden_segment_header() {
        let tmp = tempdir();
        let archive_uuid = [0x44; 16];
        let seg1 = tmp.join("archive.amber.001");
        let seg2 = tmp.join("archive.amber.002");
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, Some(120_000), None);
        {
            let mut fh = File::create(&seg1).unwrap();
            fh.write_all(&superblock).unwrap();
            fh.write_all(&[b'A'; 16]).unwrap();
        }
        {
            let mut fh = File::create(&seg2).unwrap();
            fh.write_all(&superblock).unwrap();
            fh.write_all(&[b'B'; 16]).unwrap();
        }

        let mut rw = LogicalArchiveReader::open_path_rw(&seg1).unwrap();
        rw.seek(SeekFrom::Start(superblock.len() as u64 + 16))
            .unwrap();
        rw.write_all(b"CCCC").unwrap();
        rw.flush().unwrap();

        let data = fs::read(&seg2).unwrap();
        assert_eq!(&data[SUPERBLOCK_SIZE..SUPERBLOCK_SIZE + 4], b"CCCC");
        let _ = fs::remove_dir_all(tmp);
    }
