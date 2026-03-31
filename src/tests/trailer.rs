    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::superblock::pack_superblock;
    use crate::tlv::dumps_index;

    use super::*;

    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!(
            "amber-rust-trailer-test-{stamp}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn index_trailer_stays_in_final_segment() {
        let tmp = tempdir();
        let archive_uuid = [0x66; 16];
        let base = tmp.join("trailer.amber");
        let superblock = pack_superblock(0, archive_uuid, 0, 0, 262_144, 0, Some(512), None);

        let mut writer = LogicalArchiveWriter::new(&base, Some(512)).unwrap();
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
                idx.insert(
                    "version".into(),
                    TlvValue::Map({
                        let mut v = TlvMap::new();
                        v.insert("major".into(), TlvValue::U64(2));
                        v.insert("minor".into(), TlvValue::U64(0));
                        v
                    }),
                );
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

        let seg1 = base.with_extension("amber.001");
        let seg2 = base.with_extension("amber.002");
        assert!(seg2.exists());
        let seg1_data = fs::read(&seg1).unwrap();
        let seg2_data = fs::read(&seg2).unwrap();
        assert!(
            !seg1_data
                .windows(INDEX_FRAME_MAGIC.len())
                .any(|w| w == INDEX_FRAME_MAGIC)
        );
        assert!(
            !seg1_data
                .windows(INDEX_LOC_MAGIC.len())
                .any(|w| w == INDEX_LOC_MAGIC)
        );
        assert!(
            seg2_data
                .windows(INDEX_FRAME_MAGIC.len())
                .any(|w| w == INDEX_FRAME_MAGIC)
        );
        assert!(
            seg2_data
                .windows(INDEX_LOC_MAGIC.len())
                .any(|w| w == INDEX_LOC_MAGIC)
        );

        let _ = fs::remove_dir_all(tmp);
    }
