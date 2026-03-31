    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{repair_archive, repair_archive_with_progress};
    use crate::AmberError;
    use crate::append::append_to_archive;
    use crate::archiveio::LogicalArchiveReader;
    use crate::constants::{CODEC_DEFLATE, CODEC_NONE};
    use crate::corrupt::{corrupt_chunk_window, corrupt_random_chunks};
    use crate::reader::ArchiveReader;
    use crate::tlv::{get_bool, get_list, get_u64};
    use crate::writer::ArchiveWriter;

    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!(
            "amber-rust-repair-test-{stamp}-{}",
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

    fn create_noise_file(path: &std::path::Path, size: usize, seed: u64) {
        fs::write(path, deterministic_noise(size, seed)).unwrap();
    }

    fn pick_deterministic_indices(len: usize, count: usize, seed: u64) -> Vec<usize> {
        assert!(count <= len);
        let mut state = if seed == 0 { 1 } else { seed };
        let mut pool = (0..len).collect::<Vec<_>>();
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let idx = (state as usize) % pool.len();
            out.push(pool.swap_remove(idx));
        }
        out
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

    fn build_chunk_repair_archive(base: &std::path::Path) -> std::path::PathBuf {
        let src = base.join("repair-src");
        fs::create_dir_all(&src).unwrap();
        create_noise_file(&src.join("alpha.bin"), 900_000, 7);
        create_noise_file(&src.join("beta.bin"), 850_000, 11);
        create_noise_file(&src.join("gamma.bin"), 780_000, 13);
        let archive = base.join("chunk-repair.amber");
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
            .add_file("alpha.bin", &src.join("alpha.bin"), Some(CODEC_DEFLATE), None, None)
            .unwrap();
        writer
            .add_file("beta.bin", &src.join("beta.bin"), Some(CODEC_DEFLATE), None, None)
            .unwrap();
        writer
            .add_file("gamma.bin", &src.join("gamma.bin"), Some(CODEC_DEFLATE), None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();
        crate::harden::append_amcf_parity(&archive, 300_000, None, None).unwrap();
        archive
    }

    fn build_mixed_group_archive(
        base: &std::path::Path,
        password: Option<&str>,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let archive = base.join("mixed.amber");
        let base_file = base.join("big.bin");
        let small_file = base.join("tiny.bin");
        create_noise_file(&base_file, 3 * 1024 * 1024, 41);
        create_noise_file(&small_file, 128 * 1024, 43);

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
            .add_file("big.bin", &base_file, Some(CODEC_NONE), Some(65_536), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        append_to_archive(&archive, &[&small_file], password, None).unwrap();

        (archive, small_file)
    }

    fn extract_file_map(
        archive: &std::path::Path,
        password: Option<&str>,
    ) -> BTreeMap<String, Vec<u8>> {
        let mut reader =
            ArchiveReader::new_with_credentials(archive, password.map(str::to_owned), None);
        reader.open().unwrap();
        let outdir = archive
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("extract-check");
        let _ = fs::remove_dir_all(&outdir);
        fs::create_dir_all(&outdir).unwrap();
        let mut map = BTreeMap::new();
        for entry in reader.list().to_vec() {
            if entry.kind == 0 {
                let dst = outdir.join(&entry.path);
                reader.extract(&entry, &dst).unwrap();
                map.insert(entry.path.clone(), fs::read(dst).unwrap());
            }
        }
        let _ = fs::remove_dir_all(&outdir);
        map
    }

    #[test]
    fn repair_archive_recovers_single_corrupted_symbol() {
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

        let mut broken = ArchiveReader::new(&archive);
        broken.open().unwrap();
        assert!(!broken.verify().unwrap());
        drop(broken);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert!(!result.amcf_repaired.is_empty());
        assert_eq!(result.remaining_data_chunks, 0);
        assert!(result.output_path.is_some());

        let mut repaired = ArchiveReader::new(&archive);
        repaired.open().unwrap();
        assert!(repaired.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    fn run_tiny_n_repair(tmp: &std::path::Path, n: usize) {
        let archive = tmp.join(format!("tiny_n{n}.amber"));
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
        for i in 0..n {
            let path = tmp.join(format!("f{i}.bin"));
            create_noise_file(&path, 65_536, 101 + i as u64);
            writer
                .add_file(
                    &format!("f{i}.bin"),
                    &path,
                    Some(CODEC_NONE),
                    Some(65_536),
                    None,
                )
                .unwrap();
        }
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let data_syms = reader
            .symbols
            .iter()
            .filter(|sym| !sym.is_parity)
            .cloned()
            .collect::<Vec<_>>();
        assert!(data_syms.len() >= n);
        let mut targets = vec![data_syms[0].clone()];
        if data_syms.len() >= 2 {
            targets.push(data_syms[data_syms.len() - 1].clone());
        }
        drop(reader);

        let mut fh = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        for sym in &targets {
            fh.seek(SeekFrom::Start(sym.offset)).unwrap();
            let mut byte = [0u8; 1];
            fh.read_exact(&mut byte).unwrap();
            fh.seek(SeekFrom::Start(sym.offset)).unwrap();
            fh.write_all(&[byte[0] ^ 0xFF]).unwrap();
        }
        drop(fh);

        let result = repair_archive(&archive, None, None, None).unwrap();
        if !result.remaining_corrupted.is_empty() {
            let mut reader = ArchiveReader::new(&archive);
            reader.open().unwrap();
            let remaining_data = result
                .remaining_corrupted
                .iter()
                .filter(|idx| !reader.symbols[**idx as usize].is_parity)
                .copied()
                .collect::<Vec<_>>();
            assert!(remaining_data.is_empty());
        }

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
    }

    #[test]
    fn amcf_tinyn_repair_n3_n5() {
        let tmp = tempdir();
        run_tiny_n_repair(&tmp, 3);
        run_tiny_n_repair(&tmp, 5);
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn repair_archive_does_not_rebuild_encrypted_archive_without_credentials() {
        let tmp = tempdir();
        let input = tmp.join("secret.bin");
        let archive = tmp.join("repair-encrypted.amber");
        fs::write(&input, vec![0x42u8; 65_536]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(32_768),
            None,
            Some("secret"),
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
            .add_file("secret.bin", &input, None, Some(32_768), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let err = repair_archive(&archive, None, None, None).unwrap_err();
        assert!(matches!(err, AmberError::EncryptedIndexRequiresPassword(_)));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn amcf_mixed_groups_small_append_repair() {
        let tmp = tempdir();
        let (archive, _small_file) = build_mixed_group_archive(&tmp, None);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let groups = get_list(reader.index.as_ref().unwrap(), "ecc_groups").unwrap();
        assert!(!groups.is_empty());
        let gid = groups
            .iter()
            .filter_map(|group| get_u64(group, "group_id"))
            .max()
            .unwrap();
        let last = groups
            .iter()
            .find(|group| get_u64(group, "group_id") == Some(gid))
            .unwrap();
        let data_indices = get_list(last, "symbols")
            .unwrap()
            .iter()
            .filter(|sym| !get_bool(sym, "is_parity").unwrap_or(false))
            .filter_map(|sym| get_u64(sym, "symbol_index"))
            .collect::<Vec<_>>();
        assert!(data_indices.len() >= 2);
        let targets = data_indices[..2].to_vec();
        drop(reader);

        let mut fh = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        for target in &targets {
            let mut reader = ArchiveReader::new(&archive);
            reader.open().unwrap();
            let sym = reader.symbols[*target as usize].clone();
            drop(reader);
            fh.seek(SeekFrom::Start(sym.offset)).unwrap();
            let mut byte = [0u8; 1];
            fh.read_exact(&mut byte).unwrap();
            fh.seek(SeekFrom::Start(sym.offset)).unwrap();
            fh.write_all(&[byte[0] ^ 0xFF]).unwrap();
        }
        drop(fh);

        let result = repair_archive(&archive, None, None, None).unwrap();
        let fixed = result.amcf_repaired.iter().copied().collect::<std::collections::BTreeSet<_>>();
        assert!(targets.iter().any(|target| fixed.contains(target)));
        assert!(result.remaining_corrupted.is_empty());

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn encrypted_mixed_groups_small_append_repair() {
        let tmp = tempdir();
        let password = "secret";
        let (archive, _small_file) = build_mixed_group_archive(&tmp, Some(password));

        let mut reader = ArchiveReader::new_with_credentials(&archive, Some(password.into()), None);
        reader.open().unwrap();
        let groups = get_list(reader.index.as_ref().unwrap(), "ecc_groups").unwrap();
        assert!(!groups.is_empty());
        let gid = groups
            .iter()
            .filter_map(|group| get_u64(group, "group_id"))
            .max()
            .unwrap();
        let last = groups
            .iter()
            .find(|group| get_u64(group, "group_id") == Some(gid))
            .unwrap();
        let data_indices = get_list(last, "symbols")
            .unwrap()
            .iter()
            .filter(|sym| !get_bool(sym, "is_parity").unwrap_or(false))
            .filter_map(|sym| get_u64(sym, "symbol_index"))
            .collect::<Vec<_>>();
        assert!(data_indices.len() >= 2);
        let targets = data_indices[..2].to_vec();
        drop(reader);

        let mut fh = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        for target in &targets {
            let mut reader =
                ArchiveReader::new_with_credentials(&archive, Some(password.into()), None);
            reader.open().unwrap();
            let sym = reader.symbols[*target as usize].clone();
            drop(reader);
            fh.seek(SeekFrom::Start(sym.offset)).unwrap();
            let mut byte = [0u8; 1];
            fh.read_exact(&mut byte).unwrap();
            fh.seek(SeekFrom::Start(sym.offset)).unwrap();
            fh.write_all(&[byte[0] ^ 0xFF]).unwrap();
        }
        drop(fh);

        let result = repair_archive(&archive, Some(password), None, None).unwrap();
        assert!(result.remaining_corrupted.is_empty());

        let mut reader = ArchiveReader::new_with_credentials(&archive, Some(password.into()), None);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn encrypted_append_uses_credentials_and_preserves_verifiability() {
        let tmp = tempdir();
        let input_a = tmp.join("a.bin");
        let input_b = tmp.join("b.bin");
        let archive = tmp.join("append-encrypted.amber");
        fs::write(&input_a, vec![0x11u8; 40_000]).unwrap();
        fs::write(&input_b, vec![0x22u8; 50_000]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(32_768),
            None,
            Some("secret"),
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
            .add_file("a.bin", &input_a, None, Some(32_768), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        append_to_archive(&archive, &[&input_b], Some("secret"), None).unwrap();

        let mut reader = ArchiveReader::new_with_credentials(&archive, Some("secret".into()), None);
        reader.open().unwrap();
        assert_eq!(reader.list().len(), 2);
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn extract_and_diff_plain_and_encrypted_match_source_bytes() {
        let tmp = tempdir();
        let plain_dir = tmp.join("plain");
        let enc_dir = tmp.join("enc");
        fs::create_dir_all(&plain_dir).unwrap();
        fs::create_dir_all(&enc_dir).unwrap();

        let plain_archive = build_sample_archive(&plain_dir, None);
        let encrypted_archive = build_sample_archive(&enc_dir, Some("secret"));

        let plain_map = extract_file_map(&plain_archive, None);
        assert_eq!(
            plain_map["docs/a.txt"],
            fs::read(plain_dir.join("docs/a.txt")).unwrap()
        );
        assert_eq!(
            plain_map["docs/b.bin"],
            fs::read(plain_dir.join("docs/b.bin")).unwrap()
        );
        assert_eq!(
            plain_map["notes.md"],
            fs::read(plain_dir.join("notes.md")).unwrap()
        );

        let encrypted_map = extract_file_map(&encrypted_archive, Some("secret"));
        assert_eq!(
            encrypted_map["docs/a.txt"],
            fs::read(enc_dir.join("docs/a.txt")).unwrap()
        );
        assert_eq!(
            encrypted_map["docs/b.bin"],
            fs::read(enc_dir.join("docs/b.bin")).unwrap()
        );
        assert_eq!(
            encrypted_map["notes.md"],
            fs::read(enc_dir.join("notes.md")).unwrap()
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn parity_symbol_corruption_is_tolerated_when_repairing_data() {
        let tmp = tempdir();
        let archive = build_sample_archive(&tmp, None);
        crate::harden::append_amcf_parity(&archive, 300_000, None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let target_data = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity)
            .unwrap()
            .clone();
        let corrupt_parities = reader
            .symbols
            .iter()
            .filter(|sym| sym.is_parity && sym.stripe_index < 0)
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(target_data.offset)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        for parity in corrupt_parities {
            rw.seek(SeekFrom::Start(parity.offset)).unwrap();
            rw.write_all(&[0x7F]).unwrap();
        }
        rw.flush().unwrap();
        drop(rw);

        let result = repair_archive(&archive, None, None, None).unwrap();
        if !result.remaining_corrupted.is_empty() {
            let mut reader = ArchiveReader::new(&archive);
            reader.open().unwrap();
            let remaining_data = result
                .remaining_corrupted
                .iter()
                .filter(|idx| !reader.symbols[**idx as usize].is_parity)
                .copied()
                .collect::<Vec<_>>();
            assert!(remaining_data.is_empty());
        }
        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn metadata_only_archive_verify_and_repair_succeeds() {
        let tmp = tempdir();
        let archive = tmp.join("meta-only.amber");

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
            .add_dir("docs", None, None, None, None, None)
            .unwrap();
        writer
            .add_dir("docs/nested", None, None, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert!(reader.entries.iter().all(|entry| entry.kind != 0));
        drop(reader);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert_eq!(result.remaining_data_chunks, 0);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        assert!(reader.entries.iter().all(|entry| entry.kind != 0));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn repair_archive_reports_no_writeback_when_nothing_repaired() {
        let tmp = tempdir();
        let input = tmp.join("large.bin");
        let archive = tmp.join("sample.amber");
        create_noise_file(&input, 1_000_000, 19);

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(1_000_000),
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
        writer.open().unwrap();
        writer
            .add_file("large.bin", &input, Some(CODEC_NONE), Some(1_000_000), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let target_chunk = reader
            .entries
            .iter()
            .find(|entry| entry.kind == 0 && !entry.chunks.is_empty())
            .unwrap()
            .chunks[0]
            .clone();
        let chunk_symbols = reader
            .symbols
            .iter()
            .filter(|sym| !sym.is_parity && sym.record_offset == target_chunk.offset)
            .cloned()
            .collect::<Vec<_>>();
        let total_symbols = reader.symbols.len();
        assert!(chunk_symbols.len() > 1);
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(chunk_symbols[0].offset + 10)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        let before = fs::read(&archive).unwrap();
        let mut messages = Vec::new();
        let mut progress = |msg: String| messages.push(msg);
        let result =
            repair_archive_with_progress(&archive, None, None, None, Some(&mut progress)).unwrap();
        let after = fs::read(&archive).unwrap();

        assert!(result.amcf_repaired.is_empty());
        assert!(result.output_path.is_none());
        assert_eq!(result.rebuilt_index_parity_symbols, None);
        assert!(result.remaining_data_chunks > 0);
        assert_eq!(before, after);
        assert!(
            messages
                .iter()
                .any(|msg| msg == &format!("repair: scanning {total_symbols} symbols"))
        );
        assert!(messages.iter().any(|msg| msg == "repair: no symbol writeback performed"));
        assert!(!messages.iter().any(|msg| msg == "repair: writeback complete"));

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(!reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn detect_corrupted_symbols_marks_entire_bad_chunk() {
        let tmp = tempdir();
        let input = tmp.join("large.bin");
        let archive = tmp.join("sample.amber");
        create_noise_file(&input, 1_000_000, 29);

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(1_000_000),
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
        writer.open().unwrap();
        writer
            .add_file("large.bin", &input, Some(CODEC_NONE), Some(1_000_000), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let target_chunk = reader
            .entries
            .iter()
            .find(|entry| entry.kind == 0 && !entry.chunks.is_empty())
            .unwrap()
            .chunks[0]
            .clone();
        let chunk_symbols = reader
            .symbols
            .iter()
            .filter(|sym| !sym.is_parity && sym.record_offset == target_chunk.offset)
            .map(|sym| sym.symbol_index)
            .collect::<Vec<_>>();
        assert!(chunk_symbols.len() > 1);
        let first_symbol = reader.symbols[chunk_symbols[0] as usize].clone();
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(first_symbol.offset + 10)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let mut fh = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        let corrupted = super::detect_corrupted_symbols(&reader, &mut fh).unwrap();
        assert!(chunk_symbols
            .iter()
            .all(|sym_index| corrupted.contains(sym_index)));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn repair_random_chunk_corruption_on_compressed_archive() {
        let tmp = tempdir();
        let archive = build_chunk_repair_archive(&tmp);

        corrupt_random_chunks(&archive, 3, Some(7), 0, false, None, None).unwrap();
        let result = repair_archive(&archive, None, None, None).unwrap();

        assert!(result.remaining_corrupted.is_empty());
        assert!(result.detected_data_chunks > 0);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn repair_chunk_window_corruption_on_compressed_archive() {
        let tmp = tempdir();
        let archive = build_chunk_repair_archive(&tmp);

        corrupt_chunk_window(&archive, 2, 3, 0, false, None, None).unwrap();
        let result = repair_archive(&archive, None, None, None).unwrap();

        assert!(result.remaining_corrupted.is_empty());
        assert!(result.detected_data_chunks > 0);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn repair_random_chunk_corruption_on_large_single_file_archive() {
        let tmp = tempdir();
        let input = tmp.join("big.bin");
        let archive = tmp.join("large-single.amber");
        create_noise_file(&input, 12 * 1024 * 1024, 211);

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            Some(CODEC_DEFLATE),
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
            .add_file("big.bin", &input, Some(CODEC_DEFLATE), None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        corrupt_random_chunks(&archive, 4, Some(17), 0, false, None, None).unwrap();
        let result = repair_archive(&archive, None, None, None).unwrap();

        assert!(result.remaining_corrupted.is_empty());
        assert!(result.detected_data_chunks >= 1);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn random_data_losses_under_budget() {
        let tmp = tempdir();
        let archive = build_sample_archive(&tmp, None);
        crate::harden::append_amcf_parity(&archive, 500_000, None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let data_syms = reader
            .symbols
            .iter()
            .filter(|sym| !sym.is_parity)
            .cloned()
            .collect::<Vec<_>>();
        let n = data_syms.len();
        let k = std::cmp::max(1, n / 10);
        let victims = pick_deterministic_indices(n, k, 0xA51CE5EED)
            .into_iter()
            .map(|idx| data_syms[idx].clone())
            .collect::<Vec<_>>();
        drop(reader);

        let mut fh = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        for sym in &victims {
            fh.seek(SeekFrom::Start(sym.offset)).unwrap();
            let mut byte = [0u8; 1];
            fh.read_exact(&mut byte).unwrap();
            fh.seek(SeekFrom::Start(sym.offset)).unwrap();
            fh.write_all(&[byte[0] ^ 0xFF]).unwrap();
        }
        drop(fh);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert!(result.remaining_corrupted.is_empty());

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn amcf_archive_repairs_end_to_end() {
        let tmp = tempdir();
        let archive = build_sample_archive(&tmp, None);
        crate::harden::append_amcf_parity(&archive, 800_000, None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        let data_symbol = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity)
            .unwrap()
            .clone();
        let parity_symbol = reader
            .symbols
            .iter()
            .find(|sym| sym.is_parity && sym.stripe_index < 0)
            .unwrap()
            .clone();
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(data_symbol.offset + 5)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.seek(SeekFrom::Start(parity_symbol.offset + 9)).unwrap();
        rw.write_all(&[0x7F]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert!(!result.amcf_repaired.is_empty());

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let remaining_data = result
            .remaining_corrupted
            .iter()
            .filter(|idx| !reader.symbols[**idx as usize].is_parity)
            .copied()
            .collect::<Vec<_>>();
        assert!(remaining_data.is_empty());
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn multiple_append_generations_repair_latest_damage_only() {
        let tmp = tempdir();
        let base = tmp.join("base.bin");
        let append1 = tmp.join("append1.bin");
        let append2 = tmp.join("append2.bin");
        let archive = tmp.join("multi-append.amber");
        create_noise_file(&base, 2 * 1024 * 1024, 301);
        create_noise_file(&append1, 768 * 1024, 303);
        create_noise_file(&append2, 768 * 1024, 307);

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(65_536),
            Some(CODEC_NONE),
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
            .add_file("base.bin", &base, Some(CODEC_NONE), Some(65_536), None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        append_to_archive(&archive, &[&append1], None, None).unwrap();
        append_to_archive(&archive, &[&append2], None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let groups = get_list(reader.index.as_ref().unwrap(), "ecc_groups").unwrap();
        let latest_gid = groups
            .iter()
            .filter_map(|group| get_u64(group, "group_id"))
            .max()
            .unwrap();
        let latest = groups
            .iter()
            .find(|group| get_u64(group, "group_id") == Some(latest_gid))
            .unwrap();
        let latest_data_indices = get_list(latest, "symbols")
            .unwrap()
            .iter()
            .filter(|sym| !get_bool(sym, "is_parity").unwrap_or(false))
            .filter_map(|sym| get_u64(sym, "symbol_index"))
            .collect::<Vec<_>>();
        assert!(latest_data_indices.len() >= 2);
        let previous_data_indices = groups
            .iter()
            .filter(|group| get_u64(group, "group_id") != Some(latest_gid))
            .flat_map(|group| get_list(group, "symbols").into_iter().flatten())
            .filter(|sym| !get_bool(sym, "is_parity").unwrap_or(false))
            .filter_map(|sym| get_u64(sym, "symbol_index"))
            .collect::<Vec<_>>();
        let previous_tags = previous_data_indices
            .iter()
            .map(|idx| (*idx, reader.symbols[*idx as usize].tag32))
            .collect::<BTreeMap<_, _>>();
        let targets = latest_data_indices[..2].to_vec();
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        for (idx, off) in targets.iter().zip([3u64, 9]) {
            let mut reader = ArchiveReader::new(&archive);
            reader.open().unwrap();
            let sym = reader.symbols[*idx as usize].clone();
            drop(reader);
            rw.seek(SeekFrom::Start(sym.offset + off)).unwrap();
            let mut byte = [0u8; 1];
            rw.read_exact(&mut byte).unwrap();
            rw.seek(SeekFrom::Start(sym.offset + off)).unwrap();
            rw.write_all(&[byte[0] ^ 0xFF]).unwrap();
        }
        rw.flush().unwrap();
        drop(rw);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert!(result.remaining_corrupted.is_empty());

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());
        for (idx, old_tag) in previous_tags {
            assert_eq!(reader.symbols[idx as usize].tag32, old_tag);
        }

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn append_harden_repair_preserves_default_uncompressed_policy() {
        let tmp = tempdir();
        let base = tmp.join("base.bin");
        let append = tmp.join("append.bin");
        let archive = tmp.join("sample.amber");
        create_noise_file(&base, 2 * 1024 * 1024, 67);
        create_noise_file(&append, 768 * 1024, 71);

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            Some(CODEC_NONE),
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
        writer.add_file("base.bin", &base, Some(CODEC_NONE), None, None).unwrap();
        writer.finalize().unwrap();
        writer.close();

        append_to_archive(&archive, &[&append], None, None).unwrap();
        crate::harden::append_amcf_parity(&archive, 150_000, None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        let file_entries = reader
            .entries
            .iter()
            .filter(|entry| entry.kind == 0)
            .map(|entry| (entry.path.clone(), entry))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            reader.superblock.as_ref().unwrap().default_codec as u64,
            CODEC_NONE as u64
        );
        assert!(file_entries
            .values()
            .all(|entry| entry.file_codec == Some(CODEC_NONE as u64)));
        let target_chunk = file_entries["append.bin"].chunks[0].clone();
        let target_symbol = reader
            .symbols
            .iter()
            .find(|sym| !sym.is_parity && sym.record_offset == target_chunk.offset)
            .unwrap()
            .clone();
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(target_symbol.offset + 13)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        let result = repair_archive(&archive, None, None, None).unwrap();
        assert!(result.remaining_corrupted.is_empty());

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert_eq!(
            reader.superblock.as_ref().unwrap().default_codec as u64,
            CODEC_NONE as u64
        );
        assert!(reader
            .entries
            .iter()
            .filter(|entry| entry.kind == 0)
            .all(|entry| entry.file_codec == Some(CODEC_NONE as u64)));
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn append_harden_repair_preserves_compressed_policy() {
        let tmp = tempdir();
        let base = tmp.join("base.bin");
        let append = tmp.join("append.bin");
        let archive = tmp.join("sample.amber");
        create_noise_file(&base, 3 * 1024 * 1024, 73);
        create_noise_file(&append, 1024 * 1024, 79);

        let mut writer = ArchiveWriter::new(
            &archive,
            None,
            Some(CODEC_DEFLATE),
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
            .add_file("base.bin", &base, Some(CODEC_DEFLATE), None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        append_to_archive(&archive, &[&append], None, None).unwrap();
        crate::harden::append_amcf_parity(&archive, 150_000, None, None).unwrap();

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert_eq!(
            reader.superblock.as_ref().unwrap().default_codec as u64,
            CODEC_DEFLATE as u64
        );
        assert!(reader
            .entries
            .iter()
            .filter(|entry| entry.kind == 0)
            .all(|entry| entry.file_codec == Some(CODEC_DEFLATE as u64)));
        drop(reader);

        corrupt_random_chunks(&archive, 2, Some(5), 0, false, None, None).unwrap();
        let result = repair_archive(&archive, None, None, None).unwrap();
        assert!(result.remaining_corrupted.is_empty());
        assert!(result.detected_data_chunks > 0);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert_eq!(
            reader.superblock.as_ref().unwrap().default_codec as u64,
            CODEC_DEFLATE as u64
        );
        assert!(reader
            .entries
            .iter()
            .filter(|entry| entry.kind == 0)
            .all(|entry| entry.file_codec == Some(CODEC_DEFLATE as u64)));
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn encrypted_repair_and_harden_roundtrip() {
        let tmp = tempdir();
        let archive = build_sample_archive(&tmp, Some("secret"));

        let mut reader =
            ArchiveReader::new_with_credentials(&archive, Some("secret".into()), None);
        reader.open().unwrap();
        let corrupt_targets = reader
            .symbols
            .iter()
            .filter(|sym| !sym.is_parity)
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(corrupt_targets.len(), 2);
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        for (sym, off) in corrupt_targets.iter().zip([5u64, 20]) {
            rw.seek(SeekFrom::Start(sym.offset + off)).unwrap();
            let mut byte = [0u8; 1];
            rw.read_exact(&mut byte).unwrap();
            rw.seek(SeekFrom::Start(sym.offset + off)).unwrap();
            rw.write_all(&[byte[0] ^ 0xFF]).unwrap();
        }
        rw.flush().unwrap();
        drop(rw);

        let err =
            crate::harden::append_amcf_parity(&archive, 300_000, Some("secret"), None).unwrap_err();
        assert!(
            err.to_string()
                .contains("Verification failed before hardening.")
        );

        let repair = repair_archive(&archive, Some("secret"), None, None).unwrap();
        assert!(!repair.amcf_repaired.is_empty());

        let added =
            crate::harden::append_amcf_parity(&archive, 300_000, Some("secret"), None).unwrap();
        assert!(added >= 1);

        let result = repair_archive(&archive, Some("secret"), None, None).unwrap();
        assert_eq!(result.remaining_data_chunks, 0);

        let mut reader =
            ArchiveReader::new_with_credentials(&archive, Some("secret".into()), None);
        reader.open().unwrap();
        assert!(reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }
