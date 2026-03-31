    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{StagedEntry, rebuild_archive, rewrite_archive_in_place, rewrite_archive_to_path};
    use crate::AmberError;
    use crate::append::append_to_archive;
    use crate::constants::CODEC_NONE;
    use crate::globalparity::MIN_TOTAL_PARITY_ROWS_FLOOR;
    use crate::reader::ArchiveReader;
    use crate::tlv::{get_list, get_map, get_u64};
    use crate::writer::ArchiveWriter;

    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!(
            "amber-rust-mutation-test-{stamp}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn rewrite_archive_in_place_rebuilds_canonical_image() {
        let tmp = tempdir();
        let input = tmp.join("one.txt");
        fs::write(&input, b"one").unwrap();
        let archive = tmp.join("rewrite.amber");

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
            .add_file("one.txt", &input, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        rewrite_archive_in_place(
            &archive,
            None,
            None,
            None,
            Some(&|stage_root, staged_entries| {
                let target = stage_root.join("two.txt");
                fs::write(&target, b"two").unwrap();
                staged_entries.push(StagedEntry {
                    path: "two.txt".into(),
                    kind: 0,
                    fs_path: Some(target),
                    mode: Some(0o644),
                    mtime_sec: Some(0),
                    mtime_nsec: Some(0),
                    atime_sec: Some(0),
                    atime_nsec: Some(0),
                    file_codec: None,
                    chunk_size: None,
                    symlink_target: None,
                    size: 3,
                });
                Ok(())
            }),
        )
        .unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert_eq!(reader.entries.len(), 2);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rebuild_archive_returns_backup_path() {
        let tmp = tempdir();
        let input = tmp.join("one.txt");
        fs::write(&input, b"one").unwrap();
        let archive = tmp.join("backup.amber");

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
            .add_file("one.txt", &input, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let backup = rebuild_archive(&archive, None, None, ".bak").unwrap();
        assert!(backup.exists());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn append_uses_canonical_rewrite_path() {
        let tmp = tempdir();
        let input = tmp.join("one.txt");
        let add = tmp.join("two.txt");
        fs::write(&input, b"one").unwrap();
        fs::write(&add, b"two").unwrap();
        let archive = tmp.join("append.amber");

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
            .add_file("one.txt", &input, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        append_to_archive(&archive, &[add], None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert_eq!(reader.entries.iter().filter(|e| e.kind == 0).count(), 2);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rebuild_archive_roundtrip_encrypted() {
        let tmp = tempdir();
        let input = tmp.join("secret.txt");
        let archive = tmp.join("encrypted-rebuild.amber");
        fs::write(&input, b"secret payload").unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            Some("secret"),
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
            .add_file("secret.txt", &input, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut before = ArchiveReader::new_with_credentials(&archive, Some("secret".into()), None);
        before.open().unwrap();
        let before_entries = before
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        assert!(before.verify().unwrap());
        drop(before);

        let backup = rebuild_archive(&archive, Some("secret"), None, ".bak").unwrap();
        assert!(backup.exists());

        let mut after = ArchiveReader::new_with_credentials(&archive, Some("secret".into()), None);
        after.open().unwrap();
        assert!(after.verify().unwrap());
        assert_eq!(
            after.entries.iter().map(|entry| entry.path.clone()).collect::<Vec<_>>(),
            before_entries
        );
        drop(after);

        let mut backup_reader =
            ArchiveReader::new_with_credentials(&backup, Some("secret".into()), None);
        backup_reader.open().unwrap();
        assert!(backup_reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rebuild_enforces_canonical_min_total_parity_floor() {
        let tmp = tempdir();
        let archive = tmp.join("micro-rebuild.amber");
        for i in 0..9 {
            fs::write(
                tmp.join(format!("s{i:02}.txt")),
                format!("micro {i}\n").repeat(2 + (i % 3)),
            )
            .unwrap();
        }

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            None,
            None,
            None,
            None,
            Some(0),
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.min_total_parity_rows = None;
        writer.open().unwrap();
        for i in 0..9 {
            writer
                .add_file(
                    &format!("s{i:02}.txt"),
                    tmp.join(format!("s{i:02}.txt")),
                    None,
                    None,
                    None,
                )
                .unwrap();
        }
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let groups = get_list(reader.index.as_ref().unwrap(), "ecc_groups").unwrap();
        let latest = groups
            .iter()
            .max_by_key(|group| get_u64(group, "group_id").unwrap_or(0))
            .unwrap();
        let before_rows = get_map(latest, "amcf")
            .and_then(|amcf| get_list(amcf, "parity"))
            .map(|rows| rows.len())
            .unwrap_or(0);
        assert_eq!(before_rows, 2);
        drop(reader);

        rebuild_archive(&archive, None, None, ".bak").unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let groups = get_list(reader.index.as_ref().unwrap(), "ecc_groups").unwrap();
        let latest = groups
            .iter()
            .max_by_key(|group| get_u64(group, "group_id").unwrap_or(0))
            .unwrap();
        let after_rows = get_map(latest, "amcf")
            .and_then(|amcf| get_list(amcf, "parity"))
            .map(|rows| rows.len())
            .unwrap_or(0);
        assert_eq!(after_rows, MIN_TOTAL_PARITY_ROWS_FLOOR);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rewrite_archive_in_place_uses_rebuild_error_for_staging_contract_violation() {
        let tmp = tempdir();
        let input = tmp.join("one.txt");
        fs::write(&input, b"one").unwrap();
        let archive = tmp.join("rewrite-error.amber");

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
            .add_file("one.txt", &input, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let err = rewrite_archive_in_place(
            &archive,
            None,
            None,
            None,
            Some(&|_stage_root, staged_entries| {
                staged_entries.push(StagedEntry {
                    path: "broken.txt".into(),
                    kind: 0,
                    fs_path: None,
                    mode: Some(0o644),
                    mtime_sec: Some(0),
                    mtime_nsec: Some(0),
                    atime_sec: Some(0),
                    atime_nsec: Some(0),
                    file_codec: None,
                    chunk_size: None,
                    symlink_target: None,
                    size: 1,
                });
                Ok(())
            }),
        )
        .unwrap_err();

        assert!(matches!(err, AmberError::Rebuild(_)));
        assert!(
            err.to_string()
                .contains("Staged file is missing a source path")
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rewrite_archive_cleans_temp_archive_on_early_failure() {
        let tmp = tempdir();
        let input = tmp.join("one.txt");
        fs::write(&input, b"one").unwrap();
        let archive = tmp.join("cleanup.amber");

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
            .add_file("one.txt", &input, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let before = fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("amber-rewrite-"))
            .collect::<Vec<_>>();

        let err = rewrite_archive_to_path(
            &archive,
            &archive,
            None,
            None,
            false,
            ".bak",
            Some(&|_, _| Err(AmberError::Rebuild("boom".into()))),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, AmberError::Rebuild(_)));

        let after = fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("amber-rewrite-"))
            .collect::<Vec<_>>();
        assert_eq!(before, after);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn rebuild_preserves_absent_file_metadata_and_file_level_overrides() {
        let tmp = tempdir();
        let input = tmp.join("one.txt");
        let archive = tmp.join("preserve.amber");
        fs::write(&input, b"payload").unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(65_536),
            Some(1),
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
            .add_file_with_metadata(
                "one.txt",
                &input,
                Some(CODEC_NONE),
                Some(4096),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut before = ArchiveReader::new(&archive);
        before.open().unwrap();
        let entry = before
            .entries
            .iter()
            .find(|entry| entry.path == "one.txt")
            .unwrap();
        assert_eq!(entry.mode, None);
        assert_eq!(entry.mtime_sec, None);
        assert_eq!(entry.mtime_nsec, None);
        assert_eq!(entry.atime_sec, None);
        assert_eq!(entry.atime_nsec, None);
        assert_eq!(entry.file_codec, Some(CODEC_NONE as u64));
        assert_eq!(entry.chunk_size, Some(4096));
        let index_entry = get_list(before.index.as_ref().unwrap(), "entries")
            .unwrap()
            .iter()
            .find(|entry| {
                crate::tlv::get_string(entry, "path") == Some("one.txt")
            })
            .unwrap();
        assert_eq!(get_u64(index_entry, "mode"), None);
        assert_eq!(get_map(index_entry, "mtime"), None);
        assert_eq!(get_map(index_entry, "atime"), None);
        assert_eq!(get_u64(index_entry, "file_codec"), Some(CODEC_NONE as u64));
        assert_eq!(get_u64(index_entry, "chunk_size"), Some(4096));
        drop(before);

        rebuild_archive(&archive, None, None, ".bak").unwrap();

        let mut after = ArchiveReader::new(&archive);
        after.open().unwrap();
        let entry = after
            .entries
            .iter()
            .find(|entry| entry.path == "one.txt")
            .unwrap();
        assert_eq!(entry.mode, None);
        assert_eq!(entry.mtime_sec, None);
        assert_eq!(entry.mtime_nsec, None);
        assert_eq!(entry.atime_sec, None);
        assert_eq!(entry.atime_nsec, None);
        assert_eq!(entry.file_codec, Some(CODEC_NONE as u64));
        assert_eq!(entry.chunk_size, Some(4096));
        let index_entry = get_list(after.index.as_ref().unwrap(), "entries")
            .unwrap()
            .iter()
            .find(|entry| {
                crate::tlv::get_string(entry, "path") == Some("one.txt")
            })
            .unwrap();
        assert_eq!(get_u64(index_entry, "mode"), None);
        assert_eq!(get_map(index_entry, "mtime"), None);
        assert_eq!(get_map(index_entry, "atime"), None);
        assert_eq!(get_u64(index_entry, "file_codec"), Some(CODEC_NONE as u64));
        assert_eq!(get_u64(index_entry, "chunk_size"), Some(4096));

        let _ = fs::remove_dir_all(tmp);
    }
