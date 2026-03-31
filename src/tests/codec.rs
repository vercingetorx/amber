    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    use zstd::stream::write::Encoder as ZstdEncoder;

    use super::Codec;
    use crate::constants::{CODEC_DEFLATE, CODEC_ZSTD};

    #[test]
    fn codec_deflate_rejects_payload_exceeding_output_limit() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&vec![b'A'; 4096]).unwrap();
        let payload = encoder.finish().unwrap();
        let codec = Codec::new(CODEC_DEFLATE);
        let err = codec.decompress(&payload, Some(128)).unwrap_err();
        assert!(err.to_string().contains("decompression limit"));
    }

    #[test]
    fn codec_zstd_roundtrip() {
        let codec = Codec::new(CODEC_ZSTD);
        let input = vec![0x5Au8; 8192];
        let compressed = codec.compress(&input).unwrap();
        let restored = codec.decompress(&compressed, Some(input.len())).unwrap();
        assert_eq!(restored, input);
    }

    #[test]
    fn codec_zstd_rejects_payload_exceeding_output_limit() {
        let mut encoder = ZstdEncoder::new(Vec::new(), 3).unwrap();
        encoder.write_all(&vec![b'B'; 4096]).unwrap();
        let payload = encoder.finish().unwrap();
        let codec = Codec::new(CODEC_ZSTD);
        let err = codec.decompress(&payload, Some(128)).unwrap_err();
        assert!(err.to_string().contains("decompression limit"));
    }
