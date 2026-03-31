    use super::{SUPERBLOCK_SIZE, pack_superblock};

    #[test]
    fn superblock_is_128_bytes_with_u32_default_codec() {
        let superblock = pack_superblock(0, [0x01; 16], 0, 0, 262_144, 2, None, None);
        assert_eq!(SUPERBLOCK_SIZE, 128);
        assert_eq!(superblock.len(), 128);
        assert_eq!(
            u32::from_le_bytes(superblock[48..52].try_into().unwrap()),
            2
        );
        assert_eq!(
            u16::from_le_bytes(superblock[52..54].try_into().unwrap()),
            0
        );
    }
