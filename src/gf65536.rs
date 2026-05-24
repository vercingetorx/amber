const POLY: u32 = 0x1_002D;
const FIELD_SIZE: usize = 65_536;
const FIELD_ORDER: usize = FIELD_SIZE - 1;

pub fn gf65536_mul(a: u16, b: u16) -> u16 {
    let mut aa = a as u32;
    let mut bb = b as u32;
    let mut out = 0u32;
    while bb != 0 {
        if (bb & 1) != 0 {
            out ^= aa;
        }
        bb >>= 1;
        aa <<= 1;
        if (aa & FIELD_SIZE as u32) != 0 {
            aa ^= POLY;
        }
    }
    (out & 0xFFFF) as u16
}

pub fn gf65536_pow(a: u16, mut power: u32) -> u16 {
    let mut result = 1u16;
    let mut base = a;
    while power != 0 {
        if (power & 1) != 0 {
            result = gf65536_mul(result, base);
        }
        base = gf65536_mul(base, base);
        power >>= 1;
    }
    result
}

pub fn gf65536_inv(a: u16) -> u16 {
    if a == 0 {
        panic!("No inverse for zero in GF(65536)");
    }
    gf65536_pow(a, (FIELD_ORDER - 1) as u32)
}

pub fn gf65536_mul_bytes(data: &[u8], coeff: u16, output_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; output_len];
    if coeff == 0 {
        return out;
    }
    let lane_count = output_len.div_ceil(2);
    for lane in 0..lane_count {
        let lo_index = lane * 2;
        let hi_index = lo_index + 1;
        let lo = data.get(lo_index).copied().unwrap_or(0) as u16;
        let hi = data.get(hi_index).copied().unwrap_or(0) as u16;
        let value = lo | (hi << 8);
        let product = if coeff == 1 {
            value
        } else {
            gf65536_mul(value, coeff)
        };
        if lo_index < output_len {
            out[lo_index] = (product & 0x00FF) as u8;
        }
        if hi_index < output_len {
            out[hi_index] = (product >> 8) as u8;
        }
    }
    out
}

pub fn gf65536_add_bytes(dest: &mut [u8], src: &[u8]) {
    for (dst, src) in dest.iter_mut().zip(src.iter().copied()) {
        *dst ^= src;
    }
}

#[cfg(test)]
mod tests {
    use super::{gf65536_inv, gf65536_mul, gf65536_mul_bytes};

    #[test]
    fn gf65536_inverse_roundtrips_nonzero_values() {
        for value in [1u16, 2, 3, 5, 17, 257, 4097, 0xBEEF, 0xFFFF] {
            assert_eq!(gf65536_mul(value, gf65536_inv(value)), 1);
        }
    }

    #[test]
    fn gf65536_byte_lanes_roundtrip_with_padded_final_lane() {
        let data = [0x34, 0x12, 0xFE, 0xCA, 0x77];
        let coeff = 0x1234;
        let encoded = gf65536_mul_bytes(&data, coeff, data.len() + 1);
        let decoded = gf65536_mul_bytes(&encoded, gf65536_inv(coeff), data.len() + 1);
        assert_eq!(&decoded[..data.len()], data);
        assert_eq!(decoded[data.len()], 0);
    }
}
