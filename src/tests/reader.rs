    use std::fs::{self, File};
    use std::io::{Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::LogicalArchiveReader;
    use crate::AmberError;
    use crate::constants::{FLAG_ENCRYPTED, KDF_ARGON2ID_V2, RTYPE_ANCHOR, RTYPE_CHUNK};
    use crate::encryption::{ARGON_MEMORY_COST_KIB, ARGON_PARALLELISM, ARGON_TIME_COST};
    use crate::encryption::{EncryptionContext, derive_user_secret};
    use crate::hashutil::{blake3_32, merkle_leaf_from_chunk_tag};
    use crate::records::{build_chunk_header_ext, write_record};
    use crate::superblock::{SuperblockEncryptionParams, pack_superblock};
    use crate::tlv::{TlvMap, TlvValue, dumps_anchor, dumps_index};
    use crate::trailer::{INDEX_LOCATOR_SIZE, write_index_trailer_with_segments};
    use crate::writer::ArchiveWriter;

    use super::ArchiveReader;

    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!(
            "amber-rust-reader-test-{stamp}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn reader_loads_index_and_trailer_offsets() {
        let tmp = tempdir();
        let archive_uuid = [0x77; 16];
        let base = tmp.join("reader.amber");
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, Some(512), None);

        let mut writer = crate::archiveio::LogicalArchiveWriter::new(&base, Some(512)).unwrap();
        writer.write_all(&superblock).unwrap();
        writer.set_segment_header_bytes(&superblock).unwrap();
        writer.write_all(&vec![b'A'; 350]).unwrap();
        write_index_trailer_with_segments(
            &mut writer,
            None,
            archive_uuid,
            [0u8; 32],
            |segments_meta: &[TlvMap]| {
                let mut idx = TlvMap::new();
                let mut version = TlvMap::new();
                version.insert("major".into(), TlvValue::U64(3));
                version.insert("minor".into(), TlvValue::U64(0));
                idx.insert("version".into(), TlvValue::Map(version));
                idx.insert(
                    "archive_uuid".into(),
                    TlvValue::Bytes(archive_uuid.to_vec()),
                );
                idx.insert("default_chunk_size".into(), TlvValue::U64(262_144));
                idx.insert("default_codec".into(), TlvValue::U64(0));
                idx.insert("segments".into(), TlvValue::List(segments_meta.to_vec()));
                dumps_index(&idx)
            },
        )
        .unwrap();

        let mut reader = ArchiveReader::new(base.with_extension("amber.001"));
        reader.open().unwrap();
        assert!(reader.index.is_some());
        assert!(reader.index_frame_offset > 0);
        assert!(reader.index_locator_offset > reader.index_frame_offset);
        assert!(reader.index_region_start <= reader.index_frame_offset);
        assert!(reader.index_frame_offset >= reader.index_frame_len);
        assert_eq!(
            reader.index_region_start,
            reader.index_frame_offset - reader.index_frame_len
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn reader_extracts_and_verifies_plaintext_chunk_archive() {
        let tmp = tempdir();
        let archive_uuid = [0x79; 16];
        let path = tmp.join("plain.amber");
        let data = b"hello amber".to_vec();
        let tag = blake3_32(&data);
        let file_hash = blake3_32(&data);
        let merkle_root = merkle_leaf_from_chunk_tag(&tag);
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, None, None);

        let mut file = File::create(&path).unwrap();
        file.write_all(&superblock).unwrap();
        let header_ext = build_chunk_header_ext(1, 0, data.len() as u32, 0, &tag, &[0u8; 16], 0);
        let (record_offset, payload_offset, payload) =
            write_record(&mut file, RTYPE_CHUNK, 0, &header_ext, &data, None).unwrap();

        let mut idx = TlvMap::new();
        let mut version = TlvMap::new();
        version.insert("major".into(), TlvValue::U64(3));
        version.insert("minor".into(), TlvValue::U64(0));
        idx.insert("version".into(), TlvValue::Map(version));
        idx.insert(
            "archive_uuid".into(),
            TlvValue::Bytes(archive_uuid.to_vec()),
        );
        idx.insert("default_chunk_size".into(), TlvValue::U64(262_144));
        idx.insert("default_codec".into(), TlvValue::U64(0));
        idx.insert(
            "entries".into(),
            TlvValue::List(vec![{
                let mut ent = TlvMap::new();
                ent.insert("entry_id".into(), TlvValue::U64(1));
                ent.insert("kind".into(), TlvValue::U64(0));
                ent.insert("path".into(), TlvValue::String("f.txt".into()));
                ent.insert("size".into(), TlvValue::U64(data.len() as u64));
                ent.insert("file_codec".into(), TlvValue::U64(0));
                ent.insert("chunk_size".into(), TlvValue::U64(262_144));
                ent.insert(
                    "chunks".into(),
                    TlvValue::List(vec![{
                        let mut ch = TlvMap::new();
                        ch.insert("offset".into(), TlvValue::U64(record_offset));
                        ch.insert("payload_offset".into(), TlvValue::U64(payload_offset));
                        ch.insert("payload_len".into(), TlvValue::U64(payload.len() as u64));
                        ch.insert("uncompressed_len".into(), TlvValue::U64(data.len() as u64));
                        ch.insert("chunk_index".into(), TlvValue::U64(0));
                        ch.insert("blake3_32".into(), TlvValue::Bytes(tag.to_vec()));
                        ch
                    }]),
                );
                ent.insert(
                    "file_blake3_32".into(),
                    TlvValue::Bytes(file_hash.to_vec()),
                );
                ent
            }]),
        );
        idx.insert(
            "segments".into(),
            TlvValue::List(vec![{
                let mut seg = TlvMap::new();
                seg.insert("segment_index".into(), TlvValue::U64(1));
                seg.insert("physical_header_length".into(), TlvValue::U64(0));
                seg
            }]),
        );
        crate::trailer::write_index_trailer(
            &mut file,
            None,
            archive_uuid,
            &dumps_index(&idx).unwrap(),
            merkle_root,
        )
        .unwrap();
        drop(file);

        let mut reader = ArchiveReader::new(&path);
        reader.open().unwrap();
        assert_eq!(reader.list().len(), 1);
        assert!(reader.verify().unwrap());

        let out = tmp.join("out.txt");
        let entry = reader.list()[0].clone();
        reader.extract(&entry, &out).unwrap();
        assert_eq!(fs::read(out).unwrap(), data);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn reader_rejects_bad_index_frame_crc() {
        let tmp = tempdir();
        let archive_uuid = [0x78; 16];
        let path = tmp.join("badcrc.amber");
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, None, None);
        let mut file = File::create(&path).unwrap();
        file.write_all(&superblock).unwrap();
        crate::trailer::write_index_trailer(
            &mut file,
            None,
            archive_uuid,
            &dumps_index(&{
                let mut idx = TlvMap::new();
                let mut version = TlvMap::new();
                version.insert("major".into(), TlvValue::U64(3));
                version.insert("minor".into(), TlvValue::U64(0));
                idx.insert("version".into(), TlvValue::Map(version));
                idx
            })
            .unwrap(),
            [0u8; 32],
        )
        .unwrap();
        drop(file);

        let mut raw = fs::read(&path).unwrap();
        let last_frame_crc_offset = raw.len() - (2 * INDEX_LOCATOR_SIZE) - 4;
        raw[last_frame_crc_offset] ^= 0xFF;
        fs::write(&path, &raw).unwrap();

        let mut reader = ArchiveReader::new(&path);
        let err = reader.open().unwrap_err();
        assert!(matches!(err, AmberError::IndexFrame(_)));
        assert!(err.to_string().contains("Index frame CRC mismatch"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn reader_loads_ecc_groups_and_anchor_records() {
        let tmp = tempdir();
        let archive_uuid = [0x7A; 16];
        let path = tmp.join("ecc-anchor.amber");
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, None, None);
        let symbol_payload = b"sym0".to_vec();
        let symbol_tag = blake3_32(&symbol_payload);
        let merkle_root = [0u8; 32];

        let mut file = File::create(&path).unwrap();
        file.write_all(&superblock).unwrap();
        let chunk_header = build_chunk_header_ext(
            0,
            0,
            symbol_payload.len() as u32,
            0,
            &symbol_tag,
            &[0u8; 16],
            0,
        );
        let (record_offset, payload_offset, payload) = write_record(
            &mut file,
            RTYPE_CHUNK,
            0,
            &chunk_header,
            &symbol_payload,
            None,
        )
        .unwrap();

        let anchor_payload = dumps_anchor(&{
            let mut anchor = TlvMap::new();
            anchor.insert("version".into(), TlvValue::U64(1));
            anchor.insert("symbol_size".into(), TlvValue::U64(65_536));
            anchor.insert("merkle_root".into(), TlvValue::Bytes(vec![0; 32]));
            anchor.insert(
                "symbols".into(),
                TlvValue::List(vec![{
                    let mut sym = TlvMap::new();
                    sym.insert("symbol_index".into(), TlvValue::U64(0));
                    sym.insert("offset".into(), TlvValue::U64(payload_offset));
                    sym.insert("length".into(), TlvValue::U64(payload.len() as u64));
                    sym.insert("tag32".into(), TlvValue::Bytes(symbol_tag.to_vec()));
                    sym.insert("is_parity".into(), TlvValue::Bool(false));
                    sym.insert("record_offset".into(), TlvValue::U64(record_offset));
                    sym
                }]),
            );
            anchor
        })
        .unwrap();
        let (anchor_offset, _, _) =
            write_record(&mut file, RTYPE_ANCHOR, 0, b"", &anchor_payload, None).unwrap();

        let mut idx = TlvMap::new();
        let mut version = TlvMap::new();
        version.insert("major".into(), TlvValue::U64(3));
        version.insert("minor".into(), TlvValue::U64(0));
        idx.insert("version".into(), TlvValue::Map(version));
        idx.insert(
            "archive_uuid".into(),
            TlvValue::Bytes(archive_uuid.to_vec()),
        );
        idx.insert("default_chunk_size".into(), TlvValue::U64(262_144));
        idx.insert("default_codec".into(), TlvValue::U64(0));
        idx.insert(
            "segments".into(),
            TlvValue::List(vec![{
                let mut seg = TlvMap::new();
                seg.insert("segment_index".into(), TlvValue::U64(1));
                seg.insert("physical_header_length".into(), TlvValue::U64(0));
                seg
            }]),
        );
        idx.insert(
            "anchors".into(),
            TlvValue::List(vec![{
                let mut meta = TlvMap::new();
                meta.insert("offset".into(), TlvValue::U64(anchor_offset));
                meta.insert("symbol_count".into(), TlvValue::U64(1));
                meta.insert("first_symbol".into(), TlvValue::U64(0));
                meta.insert("last_symbol".into(), TlvValue::U64(0));
                meta
            }]),
        );
        idx.insert(
            "ecc_groups".into(),
            TlvValue::List(vec![{
                let mut group = TlvMap::new();
                group.insert("group_id".into(), TlvValue::U64(0));
                group.insert("symbol_size".into(), TlvValue::U64(65_536));
                group.insert(
                    "symbols".into(),
                    TlvValue::List(vec![{
                        let mut sym = TlvMap::new();
                        sym.insert("symbol_index".into(), TlvValue::U64(0));
                        sym.insert("offset".into(), TlvValue::U64(payload_offset));
                        sym.insert("length".into(), TlvValue::U64(payload.len() as u64));
                        sym.insert("tag32".into(), TlvValue::Bytes(symbol_tag.to_vec()));
                        sym.insert("record_offset".into(), TlvValue::U64(record_offset));
                        sym.insert("is_parity".into(), TlvValue::Bool(false));
                        sym
                    }]),
                );
                group.insert(
                    "amcf".into(),
                    TlvValue::Map({
                        let mut amcf = TlvMap::new();
                        amcf.insert("epsilon_ppm".into(), TlvValue::U64(0));
                        amcf.insert("parity".into(), TlvValue::List(vec![]));
                        amcf
                    }),
                );
                group
            }]),
        );

        crate::trailer::write_index_trailer(
            &mut file,
            None,
            archive_uuid,
            &dumps_index(&idx).unwrap(),
            merkle_root,
        )
        .unwrap();
        drop(file);

        let mut reader = ArchiveReader::new(&path);
        reader.open().unwrap();
        assert_eq!(reader.symbol_size, 65_536);
        assert_eq!(reader.symbols.len(), 1);
        assert_eq!(reader.symbols[0].record_offset, record_offset);
        assert_eq!(reader.anchors_meta.len(), 1);
        assert_eq!(reader.anchors_data.len(), 1);
        assert_eq!(reader.anchor_total_count, 1);
        assert_eq!(reader.anchor_fail_count, 0);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn reader_rejects_ecc_symbol_index_gap() {
        let tmp = tempdir();
        let archive_uuid = [0x7B; 16];
        let path = tmp.join("ecc-gap.amber");
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, None, None);
        let mut file = File::create(&path).unwrap();
        file.write_all(&superblock).unwrap();

        let mut idx = TlvMap::new();
        let mut version = TlvMap::new();
        version.insert("major".into(), TlvValue::U64(3));
        version.insert("minor".into(), TlvValue::U64(0));
        idx.insert("version".into(), TlvValue::Map(version));
        idx.insert(
            "archive_uuid".into(),
            TlvValue::Bytes(archive_uuid.to_vec()),
        );
        idx.insert(
            "segments".into(),
            TlvValue::List(vec![{
                let mut seg = TlvMap::new();
                seg.insert("segment_index".into(), TlvValue::U64(1));
                seg.insert("physical_header_length".into(), TlvValue::U64(0));
                seg
            }]),
        );
        idx.insert(
            "ecc_groups".into(),
            TlvValue::List(vec![{
                let mut group = TlvMap::new();
                group.insert("group_id".into(), TlvValue::U64(0));
                group.insert("symbol_size".into(), TlvValue::U64(65_536));
                group.insert(
                    "symbols".into(),
                    TlvValue::List(vec![{
                        let mut sym = TlvMap::new();
                        sym.insert("symbol_index".into(), TlvValue::U64(1));
                        sym.insert("offset".into(), TlvValue::U64(0));
                        sym.insert("length".into(), TlvValue::U64(1));
                        sym.insert("tag32".into(), TlvValue::Bytes(vec![0; 32]));
                        sym.insert("record_offset".into(), TlvValue::U64(0));
                        sym.insert("is_parity".into(), TlvValue::Bool(false));
                        sym
                    }]),
                );
                group.insert(
                    "amcf".into(),
                    TlvValue::Map({
                        let mut amcf = TlvMap::new();
                        amcf.insert("epsilon_ppm".into(), TlvValue::U64(0));
                        amcf.insert("parity".into(), TlvValue::List(vec![]));
                        amcf
                    }),
                );
                group
            }]),
        );
        crate::trailer::write_index_trailer(
            &mut file,
            None,
            archive_uuid,
            &dumps_index(&idx).unwrap(),
            [0u8; 32],
        )
        .unwrap();
        drop(file);

        let mut reader = ArchiveReader::new(&path);
        let err = reader.open().unwrap_err();
        assert!(matches!(err, AmberError::SymbolIndexGap(_)));
        assert!(err.to_string().contains("ECC symbol index gap detected"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn reader_extracts_and_verifies_encrypted_chunk_archive() {
        let tmp = tempdir();
        let archive_uuid = [0x7C; 16];
        let path = tmp.join("enc.amber");
        let password = "secret";
        let secret = derive_user_secret(Some(password), None).unwrap().unwrap();
        let encryptor =
            EncryptionContext::create_from_secret_with_salt(&secret, [9u8; 16]).unwrap();
        let enc_params = encryptor.export_params();
        let data = b"encrypted amber".to_vec();
        let tag = blake3_32(&data);
        let file_hash = blake3_32(&data);
        let merkle_root = merkle_leaf_from_chunk_tag(&tag);
        let superblock = pack_superblock(
            FLAG_ENCRYPTED,
            archive_uuid,
            0,
            0,
            262_144,
            0,
            None,
            Some(&SuperblockEncryptionParams {
                kdf_id: KDF_ARGON2ID_V2,
                salt: enc_params.salt,
                argon_mem: enc_params.memory_cost_kib,
                argon_time: enc_params.time_cost,
                argon_lanes: enc_params.parallelism,
            }),
        );

        let mut file = File::create(&path).unwrap();
        file.write_all(&superblock).unwrap();
        let header_ext = build_chunk_header_ext(1, 0, data.len() as u32, 0, &tag, &[0u8; 16], 0);
        let (record_offset, payload_offset, payload) = write_record(
            &mut file,
            RTYPE_CHUNK,
            0,
            &header_ext,
            &data,
            Some(&encryptor),
        )
        .unwrap();

        let mut idx = TlvMap::new();
        let mut version = TlvMap::new();
        version.insert("major".into(), TlvValue::U64(3));
        version.insert("minor".into(), TlvValue::U64(0));
        idx.insert("version".into(), TlvValue::Map(version));
        idx.insert(
            "archive_uuid".into(),
            TlvValue::Bytes(archive_uuid.to_vec()),
        );
        idx.insert("default_chunk_size".into(), TlvValue::U64(262_144));
        idx.insert("default_codec".into(), TlvValue::U64(0));
        idx.insert(
            "entries".into(),
            TlvValue::List(vec![{
                let mut ent = TlvMap::new();
                ent.insert("entry_id".into(), TlvValue::U64(1));
                ent.insert("kind".into(), TlvValue::U64(0));
                ent.insert("path".into(), TlvValue::String("secret.txt".into()));
                ent.insert("size".into(), TlvValue::U64(data.len() as u64));
                ent.insert("file_codec".into(), TlvValue::U64(0));
                ent.insert("chunk_size".into(), TlvValue::U64(262_144));
                ent.insert(
                    "chunks".into(),
                    TlvValue::List(vec![{
                        let mut ch = TlvMap::new();
                        ch.insert("offset".into(), TlvValue::U64(record_offset));
                        ch.insert("payload_offset".into(), TlvValue::U64(payload_offset));
                        ch.insert("payload_len".into(), TlvValue::U64(payload.len() as u64));
                        ch.insert("uncompressed_len".into(), TlvValue::U64(data.len() as u64));
                        ch.insert("chunk_index".into(), TlvValue::U64(0));
                        ch.insert("blake3_32".into(), TlvValue::Bytes(tag.to_vec()));
                        ch
                    }]),
                );
                ent.insert(
                    "file_blake3_32".into(),
                    TlvValue::Bytes(file_hash.to_vec()),
                );
                ent
            }]),
        );
        idx.insert(
            "segments".into(),
            TlvValue::List(vec![{
                let mut seg = TlvMap::new();
                seg.insert("segment_index".into(), TlvValue::U64(1));
                seg.insert("physical_header_length".into(), TlvValue::U64(0));
                seg
            }]),
        );
        crate::trailer::write_index_trailer(
            &mut file,
            Some(&encryptor),
            archive_uuid,
            &dumps_index(&idx).unwrap(),
            merkle_root,
        )
        .unwrap();
        drop(file);

        let mut reader = ArchiveReader::new_with_credentials(&path, Some(password.into()), None);
        reader.open().unwrap();
        assert_eq!(reader.list().len(), 1);
        assert!(reader.verify().unwrap());
        let out = tmp.join("secret-out.txt");
        let entry = reader.list()[0].clone();
        reader.extract(&entry, &out).unwrap();
        assert_eq!(fs::read(out).unwrap(), data);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn reader_rejects_encrypted_archive_without_credentials() {
        let tmp = tempdir();
        let archive_uuid = [0x7D; 16];
        let path = tmp.join("enc-missing-creds.amber");
        let secret = derive_user_secret(Some("secret"), None).unwrap().unwrap();
        let encryptor =
            EncryptionContext::create_from_secret_with_salt(&secret, [10u8; 16]).unwrap();
        let enc_params = encryptor.export_params();
        let superblock = pack_superblock(
            FLAG_ENCRYPTED,
            archive_uuid,
            0,
            0,
            262_144,
            0,
            None,
            Some(&SuperblockEncryptionParams {
                kdf_id: KDF_ARGON2ID_V2,
                salt: enc_params.salt,
                argon_mem: enc_params.memory_cost_kib,
                argon_time: enc_params.time_cost,
                argon_lanes: enc_params.parallelism,
            }),
        );
        fs::write(&path, superblock).unwrap();

        let mut reader = ArchiveReader::new(&path);
        let err = reader.open().unwrap_err();
        assert!(matches!(err, AmberError::EncryptedIndexRequiresPassword(_)));
        assert!(err.to_string().contains("password or keyfile required"));

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn verify_returns_false_on_corrupted_compressed_chunk() {
        let tmp = tempdir();
        let input = tmp.join("payload.bin");
        let archive = tmp.join("corrupt-compressed.amber");
        fs::write(&input, vec![0x61u8; 220_000]).unwrap();

        let mut writer = ArchiveWriter::new(
            &archive,
            Some(32_768),
            Some(crate::constants::CODEC_DEFLATE),
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
            .add_file("payload.bin", &input, Some(crate::constants::CODEC_DEFLATE), Some(32_768), None)
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
        drop(reader);

        let mut rw = LogicalArchiveReader::open_path_rw(&archive).unwrap();
        rw.seek(SeekFrom::Start(target_chunk.payload_offset + 32)).unwrap();
        rw.write_all(&[0xFF]).unwrap();
        rw.flush().unwrap();
        drop(rw);

        let mut reader = ArchiveReader::new(&archive);
        reader.open().unwrap();
        assert!(!reader.verify().unwrap());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn encrypted_superblock_records_argon_params() {
        let tmp = tempdir();
        let input = tmp.join("secret.bin");
        let archive = tmp.join("encrypted-superblock.amber");
        fs::write(&input, vec![0x42u8; 65_536]).unwrap();

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
            .add_file("secret.bin", &input, None, None, None)
            .unwrap();
        writer.finalize().unwrap();
        writer.close();

        let mut reader = ArchiveReader::new_with_credentials(&archive, Some("secret".into()), None);
        reader.open().unwrap();
        let sb = reader.superblock.as_ref().unwrap();
        assert_eq!(sb.kdf_id, KDF_ARGON2ID_V2);
        assert_ne!(sb.kdf_salt, [0u8; 16]);
        assert_eq!(sb.argon_time_cost, ARGON_TIME_COST);
        assert_eq!(sb.argon_memory_cost, ARGON_MEMORY_COST_KIB);
        assert_eq!(sb.argon_parallelism, ARGON_PARALLELISM);
        let decryptor = reader.decryptor.as_ref().unwrap();
        let params = decryptor.export_params();
        assert_eq!(params.time_cost, ARGON_TIME_COST);
        assert_eq!(params.memory_cost_kib, ARGON_MEMORY_COST_KIB);
        assert_eq!(params.parallelism, ARGON_PARALLELISM);

        let _ = fs::remove_dir_all(tmp);
    }
