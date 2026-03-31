    use super::{EncryptionContext, derive_user_secret};

    #[test]
    fn encryption_roundtrip() {
        let secret = derive_user_secret(Some("secret"), None).unwrap().unwrap();
        let ctx = EncryptionContext::create_from_secret_with_salt(&secret, [7u8; 16]).unwrap();
        let payload = ctx.encrypt(b"aad", b"hello", b"nonce").unwrap();
        let plain = ctx.decrypt(b"aad", &payload, b"nonce").unwrap();
        assert_eq!(plain, b"hello");
    }
