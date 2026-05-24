    use super::*;

    #[test]
    fn index_segments_roundtrip() {
        let payload = dumps_index(&map_of([
            (
                "version",
                TlvValue::Map(map_of([
                    ("major", TlvValue::U64(2)),
                    ("minor", TlvValue::U64(0)),
                ])),
            ),
            ("archive_uuid", TlvValue::Bytes(vec![0x33; 16])),
            ("default_chunk_size", TlvValue::U64(262_144)),
            ("default_codec", TlvValue::U64(0)),
            (
                "segments",
                TlvValue::List(vec![
                    map_of([
                        ("segment_index", TlvValue::U64(1)),
                        ("physical_header_length", TlvValue::U64(0)),
                    ]),
                    map_of([
                        ("segment_index", TlvValue::U64(2)),
                        ("physical_header_length", TlvValue::U64(128)),
                    ]),
                ]),
            ),
        ]))
        .unwrap();
        let idx = loads_index(&payload, IndexLimits::default()).unwrap();
        let segments = get_list(&idx, "segments").unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(get_u64(&segments[0], "segment_index"), Some(1));
        assert_eq!(get_u64(&segments[1], "physical_header_length"), Some(128));
    }

    #[test]
    fn loads_index_rejects_excessive_anchor_count() {
        let payload = dumps_index(&map_of([
            (
                "version",
                TlvValue::Map(map_of([
                    ("major", TlvValue::U64(2)),
                    ("minor", TlvValue::U64(0)),
                ])),
            ),
            (
                "anchors",
                TlvValue::List(vec![
                    map_of([
                        ("offset", TlvValue::U64(10)),
                        ("symbol_count", TlvValue::U64(1)),
                        ("first_symbol", TlvValue::U64(0)),
                        ("last_symbol", TlvValue::U64(0)),
                    ]),
                    map_of([
                        ("offset", TlvValue::U64(20)),
                        ("symbol_count", TlvValue::U64(1)),
                        ("first_symbol", TlvValue::U64(1)),
                        ("last_symbol", TlvValue::U64(1)),
                    ]),
                ]),
            ),
        ]))
        .unwrap();
        let err = loads_index(
            &payload,
            IndexLimits {
                max_total_anchors: 1,
                ..IndexLimits::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("max anchors"));
    }

    #[test]
    fn loads_index_rejects_excessive_ecc_group_count() {
        let payload = dumps_index(&map_of([
            (
                "version",
                TlvValue::Map(map_of([
                    ("major", TlvValue::U64(3)),
                    ("minor", TlvValue::U64(0)),
                ])),
            ),
            (
                "ecc_groups",
                TlvValue::List(vec![
                    map_of([
                        ("group_id", TlvValue::U64(0)),
                        ("symbol_size", TlvValue::U64(65_536)),
                        ("symbols", TlvValue::List(Vec::new())),
                        (
                            "cauchy_rs",
                            TlvValue::Map(map_of([
                                ("epsilon_ppm", TlvValue::U64(0)),
                                ("parity", TlvValue::List(Vec::new())),
                            ])),
                        ),
                    ]),
                    map_of([
                        ("group_id", TlvValue::U64(1)),
                        ("symbol_size", TlvValue::U64(65_536)),
                        ("symbols", TlvValue::List(Vec::new())),
                        (
                            "cauchy_rs",
                            TlvValue::Map(map_of([
                                ("epsilon_ppm", TlvValue::U64(0)),
                                ("parity", TlvValue::List(Vec::new())),
                            ])),
                        ),
                    ]),
                ]),
            ),
        ]))
        .unwrap();
        let err = loads_index(
            &payload,
            IndexLimits {
                max_ecc_groups: 1,
                ..IndexLimits::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("max ECC groups"));
    }

    #[test]
    fn loads_index_rejects_excessive_total_symbol_count() {
        let payload = dumps_index(&map_of([
            (
                "version",
                TlvValue::Map(map_of([
                    ("major", TlvValue::U64(3)),
                    ("minor", TlvValue::U64(0)),
                ])),
            ),
            (
                "ecc_groups",
                TlvValue::List(vec![
                    map_of([
                        ("group_id", TlvValue::U64(0)),
                        ("symbol_size", TlvValue::U64(65_536)),
                        (
                            "symbols",
                            TlvValue::List(vec![map_of([
                                ("symbol_index", TlvValue::U64(0)),
                                ("offset", TlvValue::U64(0)),
                                ("length", TlvValue::U64(1)),
                                ("tag32", TlvValue::Bytes(vec![b'a'; 32])),
                                ("is_parity", TlvValue::Bool(false)),
                                ("record_offset", TlvValue::U64(0)),
                            ])]),
                        ),
                        (
                            "cauchy_rs",
                            TlvValue::Map(map_of([
                                ("epsilon_ppm", TlvValue::U64(0)),
                                ("parity", TlvValue::List(Vec::new())),
                            ])),
                        ),
                    ]),
                    map_of([
                        ("group_id", TlvValue::U64(1)),
                        ("symbol_size", TlvValue::U64(65_536)),
                        (
                            "symbols",
                            TlvValue::List(vec![map_of([
                                ("symbol_index", TlvValue::U64(1)),
                                ("offset", TlvValue::U64(1)),
                                ("length", TlvValue::U64(1)),
                                ("tag32", TlvValue::Bytes(vec![b'b'; 32])),
                                ("is_parity", TlvValue::Bool(false)),
                                ("record_offset", TlvValue::U64(1)),
                            ])]),
                        ),
                        (
                            "cauchy_rs",
                            TlvValue::Map(map_of([
                                ("epsilon_ppm", TlvValue::U64(0)),
                                ("parity", TlvValue::List(Vec::new())),
                            ])),
                        ),
                    ]),
                ]),
            ),
        ]))
        .unwrap();
        let err = loads_index(
            &payload,
            IndexLimits {
                max_total_symbols: 1,
                ..IndexLimits::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("max total symbols"));
    }

    #[test]
    fn loads_index_rejects_excessive_total_cauchy_rs_parity_count() {
        let payload = dumps_index(&map_of([
            (
                "version",
                TlvValue::Map(map_of([
                    ("major", TlvValue::U64(3)),
                    ("minor", TlvValue::U64(0)),
                ])),
            ),
            (
                "ecc_groups",
                TlvValue::List(vec![
                    map_of([
                        ("group_id", TlvValue::U64(0)),
                        ("symbol_size", TlvValue::U64(65_536)),
                        ("symbols", TlvValue::List(Vec::new())),
                        (
                            "cauchy_rs",
                            TlvValue::Map(map_of([
                                ("epsilon_ppm", TlvValue::U64(0)),
                                (
                                    "parity",
                                    TlvValue::List(vec![map_of([
                                        ("symbol_index", TlvValue::U64(0)),
                                        ("seed_id", TlvValue::U64(0)),
                                        ("offset", TlvValue::U64(0)),
                                        ("length", TlvValue::U64(1)),
                                        ("tag32", TlvValue::Bytes(vec![b'a'; 32])),
                                        ("row_count", TlvValue::U64(2)),
                                    ])]),
                                ),
                            ])),
                        ),
                    ]),
                    map_of([
                        ("group_id", TlvValue::U64(1)),
                        ("symbol_size", TlvValue::U64(65_536)),
                        ("symbols", TlvValue::List(Vec::new())),
                        (
                            "cauchy_rs",
                            TlvValue::Map(map_of([
                                ("epsilon_ppm", TlvValue::U64(0)),
                                (
                                    "parity",
                                    TlvValue::List(vec![map_of([
                                        ("symbol_index", TlvValue::U64(1)),
                                        ("seed_id", TlvValue::U64(1)),
                                        ("offset", TlvValue::U64(1)),
                                        ("length", TlvValue::U64(1)),
                                        ("tag32", TlvValue::Bytes(vec![b'b'; 32])),
                                        ("row_count", TlvValue::U64(2)),
                                    ])]),
                                ),
                            ])),
                        ),
                    ]),
                ]),
            ),
        ]))
        .unwrap();
        let err = loads_index(
            &payload,
            IndexLimits {
                max_total_cauchy_rs_parity: 1,
                ..IndexLimits::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("max total Cauchy RS parity"));
    }

    #[test]
    fn anchor_roundtrip() {
        let archive_uuid = [9u8; 16];
        let merkle_root = [1u8; 32];
        let checkpoint_hash = crate::trailer::metadata_checkpoint_hash(
            archive_uuid,
            65_536,
            merkle_root,
            b"0123456789abcdef",
            "cauchy-rs",
            8,
            7,
            1,
        );
        let payload = dumps_anchor(&map_of([
            ("version", TlvValue::U64(1)),
            ("symbol_size", TlvValue::U64(65_536)),
            ("merkle_root", TlvValue::Bytes(merkle_root.to_vec())),
            ("archive_uuid", TlvValue::Bytes(archive_uuid.to_vec())),
            ("seed_base", TlvValue::Bytes(b"0123456789abcdef".to_vec())),
            ("scheme", TlvValue::String("cauchy-rs".into())),
            ("total_symbol_count", TlvValue::U64(8)),
            ("data_symbol_count", TlvValue::U64(7)),
            ("parity_symbol_count", TlvValue::U64(1)),
            (
                "checkpoint_hash32",
                TlvValue::Bytes(checkpoint_hash.to_vec()),
            ),
            (
                "symbols",
                TlvValue::List(vec![map_of([
                    ("symbol_index", TlvValue::U64(7)),
                    ("offset", TlvValue::U64(123)),
                    ("length", TlvValue::U64(456)),
                    ("tag32", TlvValue::Bytes(vec![2; 32])),
                    ("is_parity", TlvValue::Bool(true)),
                    ("record_offset", TlvValue::U64(111)),
                ])]),
            ),
        ]))
        .unwrap();
        let anchor = loads_anchor(&payload, 1024).unwrap();
        assert_eq!(get_u64(&anchor, "version"), Some(1));
        assert_eq!(get_bytes(&anchor, "archive_uuid"), Some(archive_uuid.as_slice()));
        assert_eq!(get_u64(&anchor, "total_symbol_count"), Some(8));
        assert_eq!(get_u64(&anchor, "data_symbol_count"), Some(7));
        assert_eq!(get_u64(&anchor, "parity_symbol_count"), Some(1));
        assert_eq!(
            get_bytes(&anchor, "checkpoint_hash32"),
            Some(checkpoint_hash.as_slice())
        );
        let symbols = get_list(&anchor, "symbols").unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(get_bool(&symbols[0], "is_parity"), Some(true));
    }

    #[test]
    fn dumps_index_omits_empty_optional_string_and_rejects_empty_identity_bytes() {
        let payload = dumps_index(&map_of([
            (
                "version",
                TlvValue::Map(map_of([
                    ("major", TlvValue::U64(3)),
                    ("minor", TlvValue::U64(0)),
                ])),
            ),
            ("writer_info", TlvValue::String(String::new())),
        ]))
        .unwrap();
        let decoded = loads_index(&payload, IndexLimits::default()).unwrap();
        assert_eq!(get_string(&decoded, "writer_info"), None);

        let err = dumps_index(&map_of([
            (
                "version",
                TlvValue::Map(map_of([
                    ("major", TlvValue::U64(3)),
                    ("minor", TlvValue::U64(0)),
                ])),
            ),
            ("archive_uuid", TlvValue::Bytes(Vec::new())),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("archive_uuid"));
    }

    #[test]
    fn dumps_anchor_omits_empty_optional_scheme_and_rejects_empty_integrity_fields() {
        let archive_uuid = [3u8; 16];
        let merkle_root = [4u8; 32];
        let payload = dumps_anchor(&map_of([
            ("version", TlvValue::U64(1)),
            ("symbol_size", TlvValue::U64(65_536)),
            ("merkle_root", TlvValue::Bytes(merkle_root.to_vec())),
            ("archive_uuid", TlvValue::Bytes(archive_uuid.to_vec())),
            ("scheme", TlvValue::String(String::new())),
            ("total_symbol_count", TlvValue::U64(0)),
            ("data_symbol_count", TlvValue::U64(0)),
            ("parity_symbol_count", TlvValue::U64(0)),
            (
                "checkpoint_hash32",
                TlvValue::Bytes(
                    crate::trailer::metadata_checkpoint_hash(
                        archive_uuid,
                        65_536,
                        merkle_root,
                        &[],
                        "",
                        0,
                        0,
                        0,
                    )
                    .to_vec(),
                ),
            ),
        ]))
        .unwrap();
        let decoded = loads_anchor(&payload, 16).unwrap();
        assert_eq!(get_string(&decoded, "scheme"), None);

        let err = dumps_anchor(&map_of([
            ("version", TlvValue::U64(1)),
            ("symbol_size", TlvValue::U64(65_536)),
            ("merkle_root", TlvValue::Bytes(Vec::new())),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("anchor.merkle_root"));
    }
