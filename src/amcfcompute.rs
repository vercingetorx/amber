use std::collections::BTreeMap;

use crate::gf256::{gf_add_bytes, gf_mul_bytes};
use crate::hashutil::blake3_32;

pub fn compute_parity_payload(
    symbol_bytes: &BTreeMap<usize, Vec<u8>>,
    combo: &[(usize, u8)],
    symbol_size: usize,
) -> Vec<u8> {
    let mut parity = vec![0u8; symbol_size];
    for (sym_index, coeff) in combo.iter().copied() {
        let data = symbol_bytes
            .get(&sym_index)
            .cloned()
            .unwrap_or_else(|| vec![0u8; symbol_size]);
        let product = gf_mul_bytes(&data, coeff);
        gf_add_bytes(&mut parity, &product);
    }
    parity
}

pub fn iter_parity_payloads<F>(
    start_seed: usize,
    target: usize,
    combo_for_seed: F,
    symbol_bytes: &BTreeMap<usize, Vec<u8>>,
    symbol_size: usize,
) -> Result<Vec<(usize, Vec<u8>, [u8; 32])>, String>
where
    F: Fn(usize) -> Result<Vec<(usize, u8)>, String>,
{
    let mut out = Vec::new();
    for seed_id in start_seed..(start_seed + target) {
        let combo = combo_for_seed(seed_id)?;
        let payload = compute_parity_payload(symbol_bytes, &combo, symbol_size);
        let tag32 = blake3_32(&payload);
        out.push((seed_id, payload, tag32));
    }
    Ok(out)
}
