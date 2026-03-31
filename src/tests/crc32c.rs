    use super::crc32c;

    #[test]
    fn matches_python_behavior_for_known_vector() {
        assert_eq!(crc32c(b"123456789", 0), 0xf28417be);
    }
