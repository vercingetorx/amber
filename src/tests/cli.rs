    use std::fs;
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        ExistsMode, ScrubOptions, SealOptions, UnsealOptions, append_command, archive_info,
        default_repaired_output_path, harden_command, list_archive, parse_part_size,
        rebuild_command, repair_command, scrub_archives, scrub_summary_json, seal_archive,
        unseal_archive, verify_archive,
    };
    use crate::archiveio::LogicalArchiveReader;
    use crate::constants::{CODEC_DEFLATE, CODEC_NONE, INDEX_FRAME_MAGIC, INDEX_LOC_MAGIC};
    use crate::reader::ArchiveReader;
    use crate::writer::ArchiveWriter;

    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!(
            "amber-rust-cli-test-{stamp}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn assert_single_live_trailer(archive: &std::path::Path) {
        let mut reader = ArchiveReader::new(archive);
        reader.open().unwrap();
        let region_start = reader.index_region_start as usize;
        drop(reader);
        let data = fs::read(archive).unwrap();
        assert_eq!(
            data.windows(INDEX_LOC_MAGIC.len())
                .filter(|w| *w == INDEX_LOC_MAGIC)
                .count(),
            2
        );
        assert!(
            data.windows(INDEX_FRAME_MAGIC.len())
                .position(|w| w == INDEX_FRAME_MAGIC)
                .unwrap()
                == region_start
        );
        assert_eq!(
            data[..region_start]
                .windows(INDEX_LOC_MAGIC.len())
                .filter(|w| *w == INDEX_LOC_MAGIC)
                .count(),
            0
        );
        assert!(
            data[region_start..]
                .windows(INDEX_FRAME_MAGIC.len())
                .filter(|w| *w == INDEX_FRAME_MAGIC)
                .count()
                >= 2
        );
    }

    fn entry_signature_map(
        reader: &ArchiveReader,
    ) -> std::collections::BTreeMap<String, (u64, u64, Option<u64>, Option<String>)> {
        let mut map = std::collections::BTreeMap::new();
        for entry in reader.list() {
            map.insert(
                entry.path.clone(),
                (
                    entry.kind,
                    if entry.kind == 0 { entry.size } else { 0 },
                    entry.mode,
                    entry.symlink_target.clone(),
                ),
            );
        }
        map
    }

    #[test]
    fn parse_part_size_supports_suffixes() {
        assert_eq!(parse_part_size("700M").unwrap(), 700 * 1024 * 1024);
        assert_eq!(parse_part_size("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_part_size("1024").unwrap(), 1024);
    }

    #[test]
    fn parse_part_size_rejects_overflow() {
        assert!(parse_part_size("18446744073709551616").is_err());
        assert!(parse_part_size("17179869184TiB").is_err());
    }

    #[test]
    fn seal_multiple_relative_inputs_to_relative_output() {
        let tmp = tempdir();
        let cwd = std::env::current_dir().unwrap();
        let input_a = tmp.join("a.jpeg");
        let input_b = tmp.join("b.jpeg");
        fs::write(&input_a, b"alpha").unwrap();
        fs::write(&input_b, b"beta").unwrap();

        std::env::set_current_dir(&tmp).unwrap();
        let wrapped = seal_archive(
            &[PathBuf::from("a.jpeg"), PathBuf::from("b.jpeg")],
            &SealOptions {
                output: Some(PathBuf::from("wrapped.amber")),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        );
        std::env::set_current_dir(cwd).unwrap();

        assert!(wrapped.is_ok(), "{wrapped:?}");
        assert!(tmp.join("wrapped.amber").exists());
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn list_archive_accepts_relative_archive_path_from_cwd() {
        let tmp = tempdir();
        let cwd = std::env::current_dir().unwrap();
        let input = tmp.join("payload.txt");
        fs::write(&input, b"payload").unwrap();

        seal_archive(
            &[&input],
            &SealOptions {
                output: Some(tmp.join("test.amber")),
                password: Some("secret".to_owned()),
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        std::env::set_current_dir(&tmp).unwrap();
        let listed = list_archive("test.amber", Some("secret"), None);
        std::env::set_current_dir(cwd).unwrap();

        assert!(listed.is_ok(), "{listed:?}");
        assert_eq!(listed.unwrap().entries[0].path, "payload.txt");
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn seal_list_info_verify_and_append_roundtrip() {
        let tmp = tempdir();
        let input_a = tmp.join("a.txt");
        let input_b = tmp.join("b.txt");
        let archive = tmp.join("cli.amber");
        fs::write(&input_a, b"alpha").unwrap();
        fs::write(&input_b, b"beta").unwrap();

        let summary = seal_archive(
            &[&input_a],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: None,
                compress: true,
                part_size: None,
            },
        )
        .unwrap();
        assert_eq!(summary.file_count, 1);

        let listed = list_archive(&archive, None, None).unwrap();
        assert_eq!(listed.entries.len(), 1);
        assert_eq!(listed.entries[0].path, "a.txt");

        let info = archive_info(&archive, None, None).unwrap();
        assert_eq!(info.file_count, 1);
        assert_eq!(info.entry_count, 1);

        let verify = verify_archive(&archive, None, None).unwrap();
        assert!(verify.ok);

        append_command(&archive, &[&input_b], None, None).unwrap();
        let listed = list_archive(&archive, None, None).unwrap();
        assert_eq!(listed.entries.len(), 2);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn seal_defaults_to_no_compression_and_compress_sets_deflate() {
        let tmp = tempdir();
        let plain_input = tmp.join("plain.txt");
        let compressed_input = tmp.join("compressed.txt");
        let plain_archive = tmp.join("plain.amber");
        let compressed_archive = tmp.join("compressed.amber");
        fs::write(&plain_input, b"alpha").unwrap();
        fs::write(&compressed_input, b"beta").unwrap();

        seal_archive(
            &[&plain_input],
            &SealOptions {
                output: Some(plain_archive.clone()),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();
        let plain_info = archive_info(&plain_archive, None, None).unwrap();
        assert_eq!(plain_info.default_codec, Some(CODEC_NONE as u64));

        seal_archive(
            &[&compressed_input],
            &SealOptions {
                output: Some(compressed_archive.clone()),
                password: None,
                keyfile: None,
                compress: true,
                part_size: None,
            },
        )
        .unwrap();
        let compressed_info = archive_info(&compressed_archive, None, None).unwrap();
        assert_eq!(compressed_info.default_codec, Some(CODEC_DEFLATE as u64));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn unseal_archive_extracts_and_renames_conflicts() {
        let tmp = tempdir();
        let archive = tmp.join("unseal.amber");
        let input = tmp.join("payload.txt");
        fs::write(&input, b"payload").unwrap();

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
            .add_dir("docs", Some(0o755), Some(1), Some(2), Some(3), Some(4))
            .unwrap();
        writer
            .add_file("docs/payload.txt", &input, None, None, Some(0o644))
            .unwrap();
        #[cfg(unix)]
        writer.add_symlink("docs/link.txt", "payload.txt").unwrap();
        writer.finalize().unwrap();
        writer.close();

        let outdir = tmp.join("out");
        let summary = unseal_archive(
            &archive,
            &UnsealOptions {
                outdir: outdir.clone(),
                password: None,
                keyfile: None,
                paths: Vec::new(),
                exists: ExistsMode::Rename,
            },
        )
        .unwrap();
        assert_eq!(summary.extracted_files, 1);
        assert!(outdir.join("docs/payload.txt").exists());
        #[cfg(unix)]
        assert_eq!(
            fs::read_link(outdir.join("docs/link.txt")).unwrap(),
            PathBuf::from("payload.txt")
        );

        let summary = unseal_archive(
            &archive,
            &UnsealOptions {
                outdir: outdir.clone(),
                password: None,
                keyfile: None,
                paths: vec!["docs/payload.txt".into()],
                exists: ExistsMode::Rename,
            },
        )
        .unwrap();
        assert_eq!(summary.renamed_entries, 1);
        assert!(outdir.join("docs/payload (1).txt").exists());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn unseal_archive_restores_directory_metadata() {
        let tmp = tempdir();
        let archive = tmp.join("dir-meta.amber");
        let outdir = tmp.join("out");
        let mtime_sec = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_123);
        let atime_sec = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001);

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
            .add_dir(
                "tracked",
                Some(0o705),
                Some(mtime_sec.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                Some(0),
                Some(atime_sec.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                Some(0),
            )
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        unseal_archive(
            &archive,
            &UnsealOptions {
                outdir: outdir.clone(),
                password: None,
                keyfile: None,
                paths: Vec::new(),
                exists: ExistsMode::Rename,
            },
        )
        .unwrap();

        let extracted = outdir.join("tracked");
        assert!(extracted.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&extracted).unwrap().permissions().mode() & 0o7777,
                0o705
            );
        }
        let extracted_mtime = fs::metadata(&extracted)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            extracted_mtime,
            mtime_sec
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scrub_success_and_recursion_and_json() {
        let tmp = tempdir();
        let outer_archive = tmp.join("outer.amber");
        let nested = tmp.join("nested");
        let inner_archive = nested.join("inner.amber");
        let outer_src = tmp.join("outer_src");
        let inner_src = nested.join("inner_src");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(&outer_src).unwrap();
        fs::create_dir_all(&inner_src).unwrap();
        fs::write(outer_src.join("file.txt"), b"alpha").unwrap();
        fs::write(inner_src.join("file.txt"), b"beta").unwrap();

        seal_archive(
            &[&outer_src],
            &SealOptions {
                output: Some(outer_archive.clone()),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();
        seal_archive(
            &[&inner_src],
            &SealOptions {
                output: Some(inner_archive.clone()),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        let nonrecursive = scrub_archives(
            &[&tmp],
            &ScrubOptions {
                recursive: false,
                jobs: 4,
                password: None,
                keyfile: None,
                repair: false,
                safe: false,
                harden_extra: 0,
            },
        )
        .unwrap();
        assert_eq!(nonrecursive.ok, 1);
        assert_eq!(nonrecursive.failed, 0);

        let recursive = scrub_archives(
            &[&tmp],
            &ScrubOptions {
                recursive: true,
                jobs: 4,
                password: None,
                keyfile: None,
                repair: true,
                safe: false,
                harden_extra: 20_000,
            },
        )
        .unwrap();
        assert_eq!(recursive.ok, 2);
        assert_eq!(recursive.repaired, 0);
        let json = scrub_summary_json(&recursive).unwrap();
        assert!(json.contains("\"ok\":2"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scrub_detects_corruption() {
        let tmp = tempdir();
        let archive = tmp.join("sample.amber");
        let input = tmp.join("payload.bin");
        fs::write(&input, vec![0x51u8; 220_000]).unwrap();

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
        rw.write_all(&[0x17]).unwrap();
        rw.flush().unwrap();

        let summary = scrub_archives(
            &[&tmp],
            &ScrubOptions {
                recursive: false,
                jobs: 2,
                password: None,
                keyfile: None,
                repair: false,
                safe: false,
                harden_extra: 0,
            },
        )
        .unwrap();
        assert_eq!(summary.ok, 0);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.results[0].status, "fail");

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scrub_recursive_repairs_multipart_archive() {
        let tmp = tempdir();
        let src = tmp.join("src");
        let nested = tmp.join("nested");
        let archive = nested.join("multi.amber");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&nested).unwrap();
        fs::write(src.join("file.bin"), vec![0x61u8; 3 * 1024 * 1024]).unwrap();

        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: None,
                compress: true,
                part_size: Some(350_000),
            },
        )
        .unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let target_chunk = reader
            .entries
            .iter()
            .find(|entry| entry.kind == 0 && !entry.chunks.is_empty())
            .unwrap()
            .chunks[0]
            .clone();
        drop(reader);

        let seg2 = nested.join("multi.amber.002");
        let mut rw = LogicalArchiveReader::open_path_rw(&seg2).unwrap();
        rw.seek(SeekFrom::Start(target_chunk.payload_offset + 10))
            .unwrap();
        rw.write_all(&[0x22]).unwrap();
        rw.flush().unwrap();

        let summary = scrub_archives(
            &[&tmp],
            &ScrubOptions {
                recursive: true,
                jobs: 4,
                password: None,
                keyfile: None,
                repair: true,
                safe: false,
                harden_extra: 0,
            },
        )
        .unwrap();
        assert_eq!(summary.ok, 1);
        assert_eq!(summary.repaired, 1);
        assert_eq!(summary.results[0].status, "repaired");

        let verify = verify_archive(&archive, None, None).unwrap();
        assert!(verify.ok);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scrub_skips_locked_encrypted_archive() {
        let tmp = tempdir();
        let src = tmp.join("encsrc");
        let archive = tmp.join("enc.amber");
        let keyfile = tmp.join("key.bin");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.txt"), b"secret").unwrap();
        fs::write(&keyfile, vec![0x33u8; 64]).unwrap();

        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive),
                password: None,
                keyfile: Some(keyfile),
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        let summary = scrub_archives(
            &[&tmp],
            &ScrubOptions {
                recursive: false,
                jobs: 2,
                password: None,
                keyfile: None,
                repair: false,
                safe: false,
                harden_extra: 0,
            },
        )
        .unwrap();
        assert_eq!(summary.ok, 0);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.results[0].status, "skip:locked");

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn default_repaired_output_path_matches_single_and_multipart_rules() {
        let tmp = tempdir();
        let single = tmp.join("sample.amber");
        fs::write(&single, b"stub").unwrap();
        assert_eq!(
            default_repaired_output_path(&single).unwrap(),
            tmp.join("sample.repaired.amber")
        );

        let multi = tmp.join("multi.amber");
        fs::write(tmp.join("multi.amber.001"), b"one").unwrap();
        fs::write(tmp.join("multi.amber.002"), b"two").unwrap();
        assert_eq!(
            default_repaired_output_path(&multi).unwrap(),
            tmp.join("multi.amber.repaired")
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn multipart_commands_work_via_middle_segment() {
        let tmp = tempdir();
        let src = tmp.join("src");
        let append_src = tmp.join("append-src");
        let archive = tmp.join("multi.amber");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&append_src).unwrap();
        fs::write(src.join("file.bin"), vec![0x41u8; 3 * 1024 * 1024]).unwrap();
        fs::write(append_src.join("extra.txt"), b"extra").unwrap();

        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: None,
                compress: true,
                part_size: Some(350_000),
            },
        )
        .unwrap();

        let middle = tmp.join("multi.amber.002");
        assert!(middle.exists());

        append_command(&middle, &[&append_src], None, None).unwrap();
        let verify = verify_archive(&middle, None, None).unwrap();
        assert!(verify.ok);

        let added = harden_command(&middle, 30_000, None, None).unwrap();
        assert!(added > 0);
        assert!(verify_archive(&archive, None, None).unwrap().ok);

        let backup = rebuild_command(&middle, None, None).unwrap();
        assert!(backup.exists());
        assert!(verify_archive(&archive, None, None).unwrap().ok);

        let listed = list_archive(&archive, None, None).unwrap();
        assert!(
            listed
                .entries
                .iter()
                .any(|entry| entry.path == "append-src/extra.txt")
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn repair_safe_copy_from_middle_segment_preserves_original() {
        let tmp = tempdir();
        let input = tmp.join("payload.bin");
        let archive = tmp.join("repair.amber");
        fs::write(&input, vec![0x61u8; 220_000]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(32_768),
            None,
            None,
            None,
            Some(350_000),
            None,
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

        let middle = tmp.join("repair.amber.002");
        let mut rw = LogicalArchiveReader::open_path_rw(&middle).unwrap();
        rw.seek(SeekFrom::Start(target_symbol.offset)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        assert!(!verify_archive(&archive, None, None).unwrap().ok);

        let result = repair_command(&middle, true, None, None, None).unwrap();
        let repaired = result.output_path.unwrap();
        assert_eq!(repaired, tmp.join("repair.amber.repaired"));
        assert!(verify_archive(&repaired, None, None).unwrap().ok);
        assert!(!verify_archive(&archive, None, None).unwrap().ok);

        let _ = fs::remove_dir_all(tmp);
    }

    #[cfg(unix)]
    #[test]
    fn seal_and_append_preserve_safe_symlink_and_reject_unsafe_symlink() {
        let tmp = tempdir();

        let safe_src = tmp.join("safe-src");
        fs::create_dir_all(&safe_src).unwrap();
        fs::write(safe_src.join("target.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("target.txt", safe_src.join("alias.txt")).unwrap();
        let safe_archive = tmp.join("safe.amber");

        seal_archive(
            &[&safe_src],
            &SealOptions {
                output: Some(safe_archive.clone()),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();
        let listed = list_archive(&safe_archive, None, None).unwrap();
        let alias = listed
            .entries
            .iter()
            .find(|entry| entry.path == "safe-src/alias.txt")
            .unwrap();
        assert_eq!(alias.kind, 2);
        assert_eq!(alias.symlink_target.as_deref(), Some("target.txt"));

        let unsafe_src = tmp.join("unsafe-src");
        fs::create_dir_all(&unsafe_src).unwrap();
        fs::write(tmp.join("outside.txt"), b"secret").unwrap();
        std::os::unix::fs::symlink("../outside.txt", unsafe_src.join("alias.txt")).unwrap();
        let unsafe_archive = tmp.join("unsafe.amber");
        let err = seal_archive(
            &[&unsafe_src],
            &SealOptions {
                output: Some(unsafe_archive),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("Symlink target may not contain"));

        let append_base = tmp.join("base.txt");
        fs::write(&append_base, b"base").unwrap();
        let append_archive = tmp.join("append.amber");
        seal_archive(
            &[&append_base],
            &SealOptions {
                output: Some(append_archive.clone()),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        let append_safe = tmp.join("append-safe");
        fs::create_dir_all(&append_safe).unwrap();
        fs::write(append_safe.join("target.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("target.txt", append_safe.join("alias.txt")).unwrap();
        append_command(&append_archive, &[&append_safe], None, None).unwrap();
        let listed = list_archive(&append_archive, None, None).unwrap();
        let alias = listed
            .entries
            .iter()
            .find(|entry| entry.path == "append-safe/alias.txt")
            .unwrap();
        assert_eq!(alias.kind, 2);
        assert_eq!(alias.symlink_target.as_deref(), Some("target.txt"));

        let append_unsafe = tmp.join("append-unsafe");
        fs::create_dir_all(&append_unsafe).unwrap();
        std::os::unix::fs::symlink("../outside.txt", append_unsafe.join("alias.txt")).unwrap();
        let err = append_command(&append_archive, &[&append_unsafe], None, None).unwrap_err();
        assert!(err.to_string().contains("Symlink target may not contain"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn append_inherits_archive_default_codec_and_commits_single_live_trailer() {
        let tmp = tempdir();
        let base = tmp.join("base.bin");
        let append = tmp.join("append.bin");
        let archive = tmp.join("append-codec.amber");
        fs::write(&base, vec![0x11u8; 512 * 1024]).unwrap();
        fs::write(&append, vec![0x22u8; 128 * 1024]).unwrap();

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
            .add_file("base.bin", &base, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        append_command(&archive, &[&append], None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let file_entries = reader
            .entries
            .iter()
            .filter(|entry| entry.kind == 0)
            .map(|entry| (entry.path.clone(), entry.file_codec))
            .collect::<std::collections::BTreeMap<_, _>>();
        let default_codec = reader.superblock.as_ref().unwrap().default_codec as u64;
        assert_eq!(file_entries["base.bin"], Some(default_codec));
        assert_eq!(file_entries["append.bin"], Some(default_codec));
        assert!(reader.verify().unwrap());
        drop(reader);

        assert_single_live_trailer(&archive);
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn harden_and_successful_repair_commit_single_live_trailer() {
        let tmp = tempdir();
        let input = tmp.join("payload.bin");
        let archive = tmp.join("canon.amber");
        fs::write(&input, vec![0x61u8; 220_000]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(32_768),
            None,
            None,
            None,
            None,
            Some(300_000),
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

        harden_command(&archive, 150_000, None, None).unwrap();
        assert_single_live_trailer(&archive);

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

        let result = repair_command(&archive, false, None, None, None).unwrap();
        assert_eq!(result.output_path.as_deref(), Some(archive.as_path()));
        assert_single_live_trailer(&archive);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn multipart_operations_preserve_part_size_policy() {
        let tmp = tempdir();
        let src = tmp.join("src");
        let archive = tmp.join("policy.amber");
        let append_file = tmp.join("added.bin");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.bin"), vec![0x41u8; 3 * 1024 * 1024]).unwrap();
        fs::write(&append_file, vec![0x52u8; 1024 * 1024]).unwrap();

        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: None,
                compress: true,
                part_size: Some(350_000),
            },
        )
        .unwrap();
        let middle = tmp.join("policy.amber.002");

        let mut reader = ArchiveReader::new(&middle);
        reader.open().unwrap();
        assert_eq!(
            reader.superblock.as_ref().unwrap().multipart_part_size,
            350_000
        );
        drop(reader);

        append_command(&middle, &[&append_file], None, None).unwrap();
        let mut reader = ArchiveReader::new(&middle);
        reader.open().unwrap();
        assert_eq!(
            reader.superblock.as_ref().unwrap().multipart_part_size,
            350_000
        );
        drop(reader);

        harden_command(&middle, 20_000, None, None).unwrap();
        let mut reader = ArchiveReader::new(&middle);
        reader.open().unwrap();
        assert_eq!(
            reader.superblock.as_ref().unwrap().multipart_part_size,
            350_000
        );
        drop(reader);

        rebuild_command(&middle, None, None).unwrap();
        let mut reader = ArchiveReader::new(&middle);
        reader.open().unwrap();
        assert_eq!(
            reader.superblock.as_ref().unwrap().multipart_part_size,
            350_000
        );
        assert!(reader.verify().unwrap());
        drop(reader);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn safe_repair_copy_preserves_entry_structure_and_content() {
        let tmp = tempdir();
        let srcdir = tmp.join("docs");
        let notes = tmp.join("notes.md");
        fs::create_dir_all(&srcdir).unwrap();
        fs::write(srcdir.join("a.txt"), b"hello world\nhello world\n").unwrap();
        fs::write(srcdir.join("b.bin"), vec![0x44u8; 4096]).unwrap();
        fs::write(&notes, b"# Title\nSome content\n").unwrap();
        let archive = tmp.join("safecopy.amber");

        seal_archive(
            &[&srcdir, &notes],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let before_entries = entry_signature_map(&reader);
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

        let result = repair_command(&archive, true, None, None, None).unwrap();
        let repaired = result.output_path.unwrap();
        assert_eq!(repaired, tmp.join("safecopy.repaired.amber"));

        let mut original_reader = ArchiveReader::new(&archive);
        original_reader.open().unwrap();
        assert!(!original_reader.verify().unwrap());
        drop(original_reader);

        let mut repaired_reader = ArchiveReader::new(&repaired);
        repaired_reader.open().unwrap();
        assert!(repaired_reader.verify().unwrap());
        let after_entries = entry_signature_map(&repaired_reader);
        assert_eq!(before_entries, after_entries);

        let outdir = tmp.join("safe-repair-extract");
        fs::create_dir_all(&outdir).unwrap();
        for entry in repaired_reader.list().to_vec() {
            if entry.kind == 0 {
                repaired_reader
                    .extract(&entry, outdir.join(&entry.path))
                    .unwrap();
            }
        }
        assert_eq!(
            fs::read(outdir.join("docs/a.txt")).unwrap(),
            fs::read(srcdir.join("a.txt")).unwrap()
        );
        assert_eq!(
            fs::read(outdir.join("docs/b.bin")).unwrap(),
            fs::read(srcdir.join("b.bin")).unwrap()
        );
        assert_eq!(
            fs::read(outdir.join("notes.md")).unwrap(),
            fs::read(notes).unwrap()
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn append_failure_leaves_existing_archive_readable() {
        let tmp = tempdir();
        let base = tmp.join("base.bin");
        let dupe = tmp.join("base.bin");
        let archive = tmp.join("failure-safe.amber");
        fs::write(&base, vec![0x11u8; 512 * 1024]).unwrap();

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
            .add_file("base.bin", &base, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let baseline = entry_signature_map(&reader);
        assert!(reader.verify().unwrap());
        drop(reader);

        let err = append_command(&archive, &[&dupe], None, None).unwrap_err();
        assert!(err.to_string().contains("archive path already exists"));

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert_eq!(entry_signature_map(&reader), baseline);

        let _ = fs::remove_dir_all(tmp);
    }
