    use std::fs;
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use amber::AmberError;
    use amber::archiveio::LogicalArchiveReader;
    use amber::cli::SealOptions;
    use amber::cli::seal_archive;
    use amber::corrupt::corrupt_random_chunks;
    use amber::reader::ArchiveReader;
    use amber::repair::ECCRepairResult;
    use clap::Parser;

    use super::{
        Args, Command, format_repair_report, parse_extra_parity_percent, render_generic_error,
        rewrite_verify_error, run,
    };

    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!(
            "amber-rust-bin-test-{stamp}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn deterministic_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = if seed == 0 { 1 } else { seed };
        let mut out = vec![0u8; len];
        for byte in &mut out {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state >> 56) as u8;
        }
        out
    }

    fn build_tree_archive(
        root: &std::path::Path,
        archive: &std::path::Path,
        compress: bool,
        part_size: Option<u64>,
    ) {
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.bin"), deterministic_bytes(3 * 1024 * 1024, 71)).unwrap();
        fs::write(src.join("b.bin"), deterministic_bytes(2 * 1024 * 1024, 73)).unwrap();
        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.to_path_buf()),
                password: None,
                keyfile: None,
                compress,
                part_size,
            },
        )
        .unwrap();
    }

    fn build_single_source_archive(
        root: &std::path::Path,
        archive: &std::path::Path,
        password: Option<String>,
        keyfile: Option<PathBuf>,
        compress: bool,
        part_size: Option<u64>,
    ) -> PathBuf {
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.bin"), deterministic_bytes(3 * 1024 * 1024, 97)).unwrap();
        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.to_path_buf()),
                password,
                keyfile,
                compress,
                part_size,
            },
        )
        .unwrap();
        src
    }

    #[test]
    fn render_generic_error_rewrites_missing_credentials_message() {
        let err = AmberError::EncryptedIndexRequiresPassword(
            "Archive is encrypted; password or keyfile required".into(),
        );
        assert_eq!(
            render_generic_error(&err),
            "Error: Archive is encrypted. Provide --password and/or --keyfile."
        );
    }

    #[test]
    fn seal_parser_accepts_interspersed_options_after_input_paths() {
        let args = Args::try_parse_from([
            "amber",
            "seal",
            "a.jpeg",
            "b.jpeg",
            "--password",
            "test-password",
            "--output",
            "test.amber",
        ])
        .unwrap();
        match args.command {
            Command::Seal {
                output,
                password,
                keyfile,
                compress,
                part_size,
                quiet,
                paths,
            } => {
                assert_eq!(output, Some(PathBuf::from("test.amber")));
                assert_eq!(password.as_deref(), Some("test-password"));
                assert_eq!(keyfile, None);
                assert!(!compress);
                assert_eq!(part_size, None);
                assert!(!quiet);
                assert_eq!(paths, vec![PathBuf::from("a.jpeg"), PathBuf::from("b.jpeg")]);
            }
            other => panic!("unexpected command parse: {other:?}"),
        }
    }

    #[test]
    fn append_parser_accepts_interspersed_options_after_input_paths() {
        let args = Args::try_parse_from([
            "amber",
            "append",
            "test.amber",
            "a.jpeg",
            "b.jpeg",
            "--password",
            "test-password",
        ])
        .unwrap();
        match args.command {
            Command::Append {
                archive,
                password,
                keyfile,
                inputs,
            } => {
                assert_eq!(archive, PathBuf::from("test.amber"));
                assert_eq!(password.as_deref(), Some("test-password"));
                assert_eq!(keyfile, None);
                assert_eq!(inputs, vec![PathBuf::from("a.jpeg"), PathBuf::from("b.jpeg")]);
            }
            other => panic!("unexpected command parse: {other:?}"),
        }
    }

    #[test]
    fn harden_percent_parser_converts_decimal_percent_to_ppm() {
        assert_eq!(parse_extra_parity_percent("3").unwrap(), 30_000);
        assert_eq!(parse_extra_parity_percent("0.5").unwrap(), 5_000);
        assert_eq!(parse_extra_parity_percent("12.3456").unwrap(), 123_456);
        assert!(parse_extra_parity_percent("12.34567").is_err());
        assert!(parse_extra_parity_percent("-1").is_err());
    }

    #[test]
    fn harden_percent_parser_rejects_overflow() {
        assert!(parse_extra_parity_percent("1844674407370956.1616").is_err());
        assert!(parse_extra_parity_percent("999999999999999999999").is_err());
    }

    #[test]
    fn format_repair_report_mentions_rebuild_before_repair() {
        let text = format_repair_report(
            &ECCRepairResult {
                amcf_repaired: vec![7],
                remaining_corrupted: Vec::new(),
                detected_data_chunks: 1,
                remaining_data_chunks: 0,
                output_path: None,
                rebuilt_index_parity_symbols: Some(26),
            },
            None,
        );
        assert!(text.contains("Repair summary: 1 repaired (1 AMCF), 0 unrepaired"));
        assert!(text.contains("AMCF repaired symbols: [7]"));
        assert!(text.contains("Rebuilt index metadata (26 AMCF parity symbol(s))"));
    }

    #[test]
    fn format_repair_report_failed_amcf_hint_does_not_suggest_hardening() {
        let text = format_repair_report(
            &ECCRepairResult {
                amcf_repaired: Vec::new(),
                remaining_corrupted: vec![1, 2, 3],
                detected_data_chunks: 2,
                remaining_data_chunks: 2,
                output_path: None,
                rebuilt_index_parity_symbols: Some(26),
            },
            None,
        );
        assert!(text.contains("Detected damaged data chunks: 2"));
        assert!(text.contains("Remaining damaged data chunks: 2"));
        assert!(text.contains(
            "Reason: surviving ECC was insufficient to recover the remaining corrupted symbols."
        ));
        assert!(text.contains("This archive is still damaged."));
        assert!(!text.contains("append more AMCF parity"));
    }

    #[test]
    fn rewrite_verify_error_reports_locked_archive() {
        let tmp = tempdir();
        let src = tmp.join("encsrc");
        let archive = tmp.join("enc.amber");
        let keyfile = tmp.join("key.bin");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.txt"), b"secret").unwrap();
        fs::write(&keyfile, vec![0x55u8; 64]).unwrap();

        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: Some(keyfile),
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        let err = rewrite_verify_error(
            &archive,
            AmberError::EncryptedIndexRequiresPassword(
                "Archive is encrypted; password or keyfile required".into(),
            ),
        );
        assert!(
            err.to_string()
                .contains("LOCKED: encrypted archive requires correct")
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn verify_exit_code_contract_matches_reference_behavior() {
        let tmp = tempdir();
        let src = tmp.join("src");
        let archive = tmp.join("sample.amber");
        let malformed = tmp.join("malformed.amber");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.bin"), vec![0x41u8; 2048]).unwrap();
        fs::write(&malformed, b"not-an-amber-archive").unwrap();

        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        let clean = run(Args {
            command: Command::Verify {
                archive: archive.clone(),
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(clean, 0);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let target = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity)
            .unwrap()
            .clone();
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(target.offset)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        let dirty = run(Args {
            command: Command::Verify {
                archive: archive.clone(),
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(dirty, 1);

        let malformed_err = run(Args {
            command: Command::Verify {
                archive: malformed,
                password: None,
                keyfile: None,
            },
        })
        .unwrap_err();
        assert!(render_generic_error(&malformed_err).starts_with("Error:"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn verify_locked_wrong_credentials_surfaces_locked_error() {
        let tmp = tempdir();
        let src = tmp.join("encsrc");
        let archive = tmp.join("enc.amber");
        let keyfile = tmp.join("key.bin");
        let wrong_keyfile = tmp.join("wrong.bin");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.txt"), b"secret").unwrap();
        fs::write(&keyfile, vec![0x11u8; 64]).unwrap();
        fs::write(&wrong_keyfile, vec![0x22u8; 64]).unwrap();

        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: Some(keyfile),
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        let err = run(Args {
            command: Command::Verify {
                archive,
                password: None,
                keyfile: Some(PathBuf::from(&wrong_keyfile)),
            },
        })
        .unwrap_err();
        assert!(err.to_string().contains("LOCKED"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn verify_rejects_multipart_segment_gap() {
        let tmp = tempdir();
        let src = tmp.join("src");
        let archive = tmp.join("multi.amber");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.bin"), deterministic_bytes(3 * 1024 * 1024, 17)).unwrap();

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
        let seg2 = PathBuf::from(format!("{}.002", archive.display()));
        assert!(seg2.exists());
        fs::remove_file(&seg2).unwrap();

        let err = run(Args {
            command: Command::Verify {
                archive,
                password: None,
                keyfile: None,
            },
        })
        .unwrap_err();
        assert!(render_generic_error(&err).contains("multipart segment gap detected"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn multipart_rebuild_rejects_conflicting_backup_namespace() {
        let tmp = tempdir();
        let src = tmp.join("src");
        let archive = tmp.join("multi.amber");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.bin"), deterministic_bytes(3 * 1024 * 1024, 29)).unwrap();

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

        fs::write(tmp.join("multi.amber.bak.003"), b"stale-backup").unwrap();

        let err = run(Args {
            command: Command::Rebuild {
                archive,
                password: None,
                keyfile: None,
            },
        })
        .unwrap_err();
        assert!(render_generic_error(&err).contains("already exists"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn harden_refuses_when_dirty() {
        let tmp = tempdir();
        let src = tmp.join("src");
        let archive = tmp.join("data.amber");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("data.bin"), vec![0x33u8; 4096]).unwrap();

        seal_archive(
            &[&src],
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
        let target = reader.symbols.iter().find(|sym| !sym.is_parity).unwrap().clone();
        drop(reader);

        let mut fh = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        fh.seek(SeekFrom::Start(target.offset)).unwrap();
        let mut b = [0u8; 1];
        use std::io::Read as _;
        fh.read_exact(&mut b).unwrap();
        fh.seek(SeekFrom::Start(target.offset)).unwrap();
        fh.write_all(&[b[0] ^ 0xAA]).unwrap();
        fh.flush().unwrap();
        drop(fh);

        let err = run(Args {
            command: Command::Harden {
                archive,
                extra_parity_ppm: 30_000,
                password: None,
                keyfile: None,
            },
        })
        .unwrap_err();
        assert!(render_generic_error(&err).contains("Verification failed"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn append_harden_and_safe_repair_workflow_roundtrip() {
        let tmp = tempdir();
        let src = tmp.join("base");
        let archive = tmp.join("data.amber");
        let appended_file = tmp.join("new.txt");
        let repaired_copy = tmp.join("data.repaired");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("base.bin"), deterministic_bytes(4096, 79)).unwrap();
        fs::write(&appended_file, b"new payload").unwrap();

        seal_archive(
            &[&src],
            &SealOptions {
                output: Some(archive.clone()),
                password: None,
                keyfile: None,
                compress: false,
                part_size: None,
            },
        )
        .unwrap();

        let append_rc = run(Args {
            command: Command::Append {
                archive: archive.clone(),
                inputs: vec![appended_file.clone()],
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(append_rc, 0);

        let verify_rc = run(Args {
            command: Command::Verify {
                archive: archive.clone(),
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(verify_rc, 0);

        let harden_rc = run(Args {
            command: Command::Harden {
                archive: archive.clone(),
                extra_parity_ppm: 10_000,
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(harden_rc, 0);

        let outdir = tmp.join("after_append");
        fs::create_dir_all(&outdir).unwrap();
        let unseal_rc = run(Args {
            command: Command::Unseal {
                archive: archive.clone(),
                outdir: outdir.clone(),
                password: None,
                keyfile: None,
                exists: super::ExistsArg::Rename,
                quiet: false,
                paths: Vec::new(),
            },
        })
        .unwrap();
        assert_eq!(unseal_rc, 0);
        let extracted = outdir.join("new.txt");
        assert!(extracted.exists());
        assert_eq!(fs::read(&extracted).unwrap(), b"new payload");

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let target = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity)
            .unwrap()
            .clone();
        drop(reader);
        let mut fh = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        fh.seek(SeekFrom::Start(target.offset)).unwrap();
        let mut byte = [0u8; 1];
        use std::io::Read as _;
        fh.read_exact(&mut byte).unwrap();
        fh.seek(SeekFrom::Start(target.offset)).unwrap();
        fh.write_all(&[byte[0] ^ 0x55]).unwrap();
        fh.flush().unwrap();
        drop(fh);

        let verify_dirty = run(Args {
            command: Command::Verify {
                archive: archive.clone(),
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(verify_dirty, 1);

        let repair_rc = run(Args {
            command: Command::Repair {
                archive: archive.clone(),
                password: None,
                keyfile: None,
                safe: true,
                output: Some(repaired_copy.clone()),
            },
        })
        .unwrap();
        assert_eq!(repair_rc, 0);
        assert!(repaired_copy.exists());

        let repaired_verify = run(Args {
            command: Command::Verify {
                archive: repaired_copy,
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(repaired_verify, 0);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn compress_archive_chunk_corruption_repair_roundtrip() {
        let tmp = tempdir();
        let archive = tmp.join("compressed.amber");
        build_tree_archive(&tmp, &archive, true, None);

        corrupt_random_chunks(&archive, 2, Some(13), 10, false, None, None).unwrap();

        let verify_dirty = run(Args {
            command: Command::Verify {
                archive: archive.clone(),
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(verify_dirty, 1);

        let repair_rc = run(Args {
            command: Command::Repair {
                archive: archive.clone(),
                password: None,
                keyfile: None,
                safe: false,
                output: None,
            },
        })
        .unwrap();
        assert_eq!(repair_rc, 0);

        let verify_ok = run(Args {
            command: Command::Verify {
                archive,
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(verify_ok, 0);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn multipart_repair_roundtrip_via_middle_segment() {
        let tmp = tempdir();
        let archive = tmp.join("multi.amber");
        build_tree_archive(&tmp, &archive, true, Some(350_000));
        let seg2 = PathBuf::from(format!("{}.002", archive.display()));

        let mut reader = ArchiveReader::new(&seg2);
        reader.open().unwrap();
        let target_chunk = reader
            .entries
            .iter()
            .find(|entry| entry.kind == 0 && !entry.chunks.is_empty())
            .unwrap()
            .chunks[0]
            .clone();
        drop(reader);
        let mut fh = LogicalArchiveReader::open_path_rw(&seg2).unwrap();
        fh.seek(SeekFrom::Start(target_chunk.payload_offset + 10))
            .unwrap();
        let mut byte = [0u8; 1];
        use std::io::Read as _;
        fh.read_exact(&mut byte).unwrap();
        fh.seek(SeekFrom::Start(target_chunk.payload_offset + 10))
            .unwrap();
        fh.write_all(&[byte[0] ^ 0xFF]).unwrap();
        fh.flush().unwrap();
        drop(fh);

        let verify_dirty = run(Args {
            command: Command::Verify {
                archive: seg2.clone(),
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(verify_dirty, 1);

        let repair_rc = run(Args {
            command: Command::Repair {
                archive: seg2.clone(),
                password: None,
                keyfile: None,
                safe: false,
                output: None,
            },
        })
        .unwrap();
        assert_eq!(repair_rc, 0);

        let verify_ok = run(Args {
            command: Command::Verify {
                archive: seg2,
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(verify_ok, 0);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn multipart_harden_via_middle_segment() {
        let tmp = tempdir();
        let archive = tmp.join("multi.amber");
        build_single_source_archive(&tmp, &archive, None, None, true, Some(350_000));
        let seg2 = PathBuf::from(format!("{}.002", archive.display()));

        let mut reader = ArchiveReader::new(&seg2);
        reader.open().unwrap();
        let before_rows = reader.amcf_parities.len();
        drop(reader);

        let rc = run(Args {
            command: Command::Harden {
                archive: seg2.clone(),
                extra_parity_ppm: 20_000,
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(rc, 0);

        let mut reader = ArchiveReader::new(&seg2);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        let after_rows = reader.amcf_parities.len();
        assert!(after_rows > before_rows);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn multipart_append_via_middle_segment() {
        let tmp = tempdir();
        let archive = tmp.join("multi.amber");
        build_single_source_archive(&tmp, &archive, None, None, true, Some(350_000));
        let seg2 = PathBuf::from(format!("{}.002", archive.display()));
        let append_file = tmp.join("added.txt");
        fs::write(&append_file, b"multipart append payload\n").unwrap();

        let rc = run(Args {
            command: Command::Append {
                archive: seg2.clone(),
                inputs: vec![append_file.clone()],
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(rc, 0);

        let verify_ok = run(Args {
            command: Command::Verify {
                archive: seg2,
                password: None,
                keyfile: None,
            },
        })
        .unwrap();
        assert_eq!(verify_ok, 0);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn encrypted_keyfile_roundtrip() {
        let tmp = tempdir();
        let archive = tmp.join("enc_keyfile.amber");
        let keyfile = tmp.join("key.bin");
        fs::write(&keyfile, deterministic_bytes(64, 101)).unwrap();
        let fixture = tmp.join("enc_keyfile");
        fs::create_dir_all(&fixture).unwrap();
        fs::write(fixture.join("file.txt"), b"secret keyfile data").unwrap();

        let rc = run(Args {
            command: Command::Seal {
                paths: vec![fixture.clone()],
                output: Some(archive.clone()),
                password: None,
                keyfile: Some(keyfile.clone()),
                compress: false,
                part_size: None,
                quiet: false,
            },
        })
        .unwrap();
        assert_eq!(rc, 0);

        let verify_rc = run(Args {
            command: Command::Verify {
                archive: archive.clone(),
                password: None,
                keyfile: Some(keyfile.clone()),
            },
        })
        .unwrap();
        assert_eq!(verify_rc, 0);

        let extract_dir = tmp.join("extract");
        fs::create_dir_all(&extract_dir).unwrap();
        let unseal_rc = run(Args {
            command: Command::Unseal {
                archive: archive.clone(),
                outdir: extract_dir.clone(),
                password: None,
                keyfile: Some(keyfile.clone()),
                exists: super::ExistsArg::Rename,
                quiet: false,
                paths: Vec::new(),
            },
        })
        .unwrap();
        assert_eq!(unseal_rc, 0);
        let extracted_root = extract_dir.join("enc_keyfile");
        let extracted_file = if extracted_root.exists() {
            extracted_root.join("file.txt")
        } else {
            extract_dir.join("file.txt")
        };
        assert_eq!(fs::read(&extracted_file).unwrap(), b"secret keyfile data");

        let rebuild_rc = run(Args {
            command: Command::Rebuild {
                archive: archive.clone(),
                password: None,
                keyfile: Some(keyfile.clone()),
            },
        })
        .unwrap();
        assert_eq!(rebuild_rc, 0);

        let rebuilt_verify = run(Args {
            command: Command::Verify {
                archive,
                password: None,
                keyfile: Some(keyfile),
            },
        })
        .unwrap();
        assert_eq!(rebuilt_verify, 0);

        let _ = fs::remove_dir_all(tmp);
    }
