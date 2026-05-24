use std::collections::BTreeMap;

use crate::gf65536::{gf65536_add_bytes, gf65536_mul_bytes};
use crate::hashutil::blake3_32;

pub fn compute_mds_payload(
    symbol_bytes: &BTreeMap<usize, Vec<u8>>,
    combo: &[(usize, u16)],
    symbol_size: usize,
) -> Vec<u8> {
    let mut parity = vec![0u8; symbol_size];
    for (sym_index, coeff) in combo.iter().copied() {
        let product = match symbol_bytes.get(&sym_index) {
            Some(data) => gf65536_mul_bytes(data, coeff, symbol_size),
            None => vec![0u8; symbol_size],
        };
        gf65536_add_bytes(&mut parity, &product);
    }
    parity
}

pub fn iter_mds_payloads<F>(
    start_row: usize,
    target: usize,
    combo_for_row: F,
    symbol_bytes: &BTreeMap<usize, Vec<u8>>,
    symbol_size: usize,
) -> Result<Vec<(usize, Vec<u8>, [u8; 32])>, String>
where
    F: Fn(usize) -> Result<Vec<(usize, u16)>, String>,
{
    let mut out = Vec::new();
    for row_id in start_row..(start_row + target) {
        let combo = combo_for_row(row_id)?;
        let payload = compute_mds_payload(symbol_bytes, &combo, symbol_size);
        let tag32 = blake3_32(&payload);
        out.push((row_id, payload, tag32));
    }
    Ok(out)
}
