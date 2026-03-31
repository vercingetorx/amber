use blake3::Hasher;

pub fn blake3_32(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

pub fn merkle_leaf_from_chunk_tag(tag32: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 40];
    data[..8].copy_from_slice(b"SS_LEAF\0");
    data[8..].copy_from_slice(tag32);
    blake3_32(&data)
}

pub fn merkle_parent(left32: &[u8; 32], right32: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 72];
    data[..8].copy_from_slice(b"SS_NODE\0");
    data[8..40].copy_from_slice(left32);
    data[40..].copy_from_slice(right32);
    blake3_32(&data)
}
