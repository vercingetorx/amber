    use std::fs;
    use std::io::{Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::append_amcf_parity;
    use crate::archiveio::LogicalArchiveReader;
    use crate::constants::CODEC_DEFLATE;
    use crate::ecc::repair_archive;
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
            "amber-rust-harden-test-{stamp}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn deterministic_noise(size: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut out = vec![0u8; size];
        for byte in &mut out {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state as u8) ^ ((state >> 8) as u8);
        }
        out
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
    fn append_amcf_parity_rewrites_archive_with_more_parity() {
        let tmp = tempdir();
        let input = tmp.join("payload.bin");
        let archive = tmp.join("harden.amber");
        fs::write(&input, vec![0x41u8; 200_000]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(32_768),
            None,
            None,
            None,
            None,
            Some(10_000),
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

        let mut before = ArchiveReader::new(&archive);
        before.open().unwrap();
        let before_parity = before.amcf_parities.len();
        assert!(before.verify().unwrap());
        drop(before);

        let added = append_amcf_parity(&archive, 30_000, None, None).unwrap();
        assert!(added > 0);

        let mut after = ArchiveReader::new(&archive);
        after.open().unwrap();
        assert!(after.verify().unwrap());
        assert_eq!(after.entries.iter().filter(|e| e.kind == 0).count(), 1);
        assert!(after.amcf_parities.len() > before_parity);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn double_harden_preserves_mixed_row_count_repair() {
        let tmp = tempdir();
        let archive = tmp.join("double-harden.amber");
        fs::write(tmp.join("alpha.bin"), deterministic_noise(900_000, 7)).unwrap();
        fs::write(tmp.join("beta.bin"), deterministic_noise(850_000, 11)).unwrap();
        fs::write(tmp.join("gamma.bin"), deterministic_noise(780_000, 13)).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(65_536),
            Some(CODEC_DEFLATE),
            None,
            None,
            None,
            Some(0),
            None,
            None,
            Some(0),
        )
        .unwrap();
        writer.open().unwrap();
        writer
            .add_file(
                "alpha.bin",
                &tmp.join("alpha.bin"),
                Some(CODEC_DEFLATE),
                None,
                None,
            )
            .unwrap();
        writer
            .add_file(
                "beta.bin",
                &tmp.join("beta.bin"),
                Some(CODEC_DEFLATE),
                None,
                None,
            )
            .unwrap();
        writer
            .add_file(
                "gamma.bin",
                &tmp.join("gamma.bin"),
                Some(CODEC_DEFLATE),
                None,
                None,
            )
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let first_added = append_amcf_parity(&archive, 150_000, None, None).unwrap();
        let second_added = append_amcf_parity(&archive, 200_000, None, None).unwrap();
        assert!(first_added > 0);
        assert!(second_added > 0);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let groups = get_list(reader.index.as_ref().unwrap(), "ecc_groups").unwrap();
        let latest = groups
            .iter()
            .max_by_key(|group| get_u64(group, "group_id").unwrap_or(0))
            .unwrap();
        let row_counts = get_map(latest, "amcf")
            .and_then(|amcf| get_list(amcf, "parity"))
            .unwrap()
            .iter()
            .filter_map(|item| get_u64(item, "row_count"))
            .filter(|row_count| *row_count > 0)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(row_counts.len(), 1);
        let victims = reader
            .symbols
            .iter()
            .filter(|sym| !sym.is_parity)
            .step_by(5)
            .take(3)
            .cloned()
            .collect::<Vec<_>>();
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        for (index, sym) in victims.iter().enumerate() {
            rw.seek(SeekFrom::Start(sym.offset + index as u64 + 1)).unwrap();
            rw.write_all(&[0xFF]).unwrap();
        }
        rw.flush().unwrap();
        drop(rw);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert!(result.remaining_corrupted.is_empty());
        assert!(result.amcf_repaired.len() >= victims.len());

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn append_global_parity_enforces_canonical_min_total_parity_floor() {
        let tmp = tempdir();
        let archive = tmp.join("micro-append.amber");
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

        let added = append_amcf_parity(&archive, 0, None, None).unwrap();
        assert_eq!(added, MIN_TOTAL_PARITY_ROWS_FLOOR - 2);

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

    #[cfg(unix)]
    #[test]
    fn harden_failure_leaves_existing_archive_readable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempdir();
        let base = tmp.join("base.bin");
        let archive = tmp.join("sample.amber");
        fs::write(&base, deterministic_noise(512 * 1024, 31)).unwrap();

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
        writer.add_file("base.bin", &base, None, None, None).unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let baseline_entries = entry_signature_map(&reader);
        let baseline_rows = reader.amcf_parities.len();
        assert!(reader.verify().unwrap());
        drop(reader);
        let before = fs::read(&archive).unwrap();

        let original_mode = fs::metadata(&tmp).unwrap().permissions().mode();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o555)).unwrap();

        let err = append_amcf_parity(&archive, 150_000, None, None).unwrap_err();

        fs::set_permissions(&tmp, fs::Permissions::from_mode(original_mode)).unwrap();

        assert!(
            err.to_string().contains("Permission denied")
                || err.to_string().contains("permission denied")
        );

        let after = fs::read(&archive).unwrap();
        assert_eq!(before, after);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert_eq!(entry_signature_map(&reader), baseline_entries);
        assert_eq!(reader.amcf_parities.len(), baseline_rows);

        let _ = fs::remove_dir_all(tmp);
    }
