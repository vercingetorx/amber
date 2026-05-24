use std::sync::OnceLock;

const POLY: u32 = 0x1_002D;
const FIELD_SIZE: usize = 65_536;
const FIELD_ORDER: usize = FIELD_SIZE - 1;

struct GfTables {
    log: Box<[u16; FIELD_SIZE]>,
    exp: Box<[u16; FIELD_ORDER * 2]>,
}

static TABLES: OnceLock<GfTables> = OnceLock::new();

pub fn gf65536_mul(a: u16, b: u16) -> u16 {
    gf65536_mul_table(a, b)
}

pub fn gf65536_inv(a: u16) -> u16 {
    if a == 0 {
        panic!("No inverse for zero in GF(65536)");
    }
    let tables = gf_tables();
    let log = tables.log[a as usize] as usize;
    tables.exp[FIELD_ORDER - log]
}

fn gf_tables() -> &'static GfTables {
    TABLES.get_or_init(build_tables)
}

fn build_tables() -> GfTables {
    let mut log = Box::new([0u16; FIELD_SIZE]);
    let mut exp = Box::new([0u16; FIELD_ORDER * 2]);
    let mut value = 1u16;
    for (i, slot) in exp.iter_mut().take(FIELD_ORDER).enumerate() {
        *slot = value;
        log[value as usize] = i as u16;
        value = gf65536_mul_slow(value, 2);
    }
    for i in FIELD_ORDER..(FIELD_ORDER * 2) {
        exp[i] = exp[i - FIELD_ORDER];
    }
    debug_assert_eq!(value, 1);
    GfTables { log, exp }
}

fn gf65536_mul_table(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    if a == 1 {
        return b;
    }
    if b == 1 {
        return a;
    }
    let tables = gf_tables();
    let log_sum = tables.log[a as usize] as usize + tables.log[b as usize] as usize;
    tables.exp[log_sum]
}

fn gf65536_mul_slow(a: u16, b: u16) -> u16 {
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

#[cfg(test)]
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

pub fn gf65536_mul_bytes(data: &[u8], coeff: u16, output_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; output_len];
    gf65536_mul_add_bytes(&mut out, data, coeff);
    out
}

pub fn gf65536_mul_add_bytes(dest: &mut [u8], data: &[u8], coeff: u16) {
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        let copy_len = dest.len().min(data.len());
        gf65536_add_bytes(&mut dest[..copy_len], &data[..copy_len]);
        return;
    }
    let coeff_table = CoeffTable::new(coeff);
    let lane_count = dest.len().div_ceil(2);
    for lane in 0..lane_count {
        let lo_index = lane * 2;
        let hi_index = lo_index + 1;
        let lo = data.get(lo_index).copied().unwrap_or(0) as u16;
        let hi = data.get(hi_index).copied().unwrap_or(0) as u16;
        let value = lo | (hi << 8);
        let product = coeff_table.mul(value);
        if lo_index < dest.len() {
            dest[lo_index] ^= (product & 0x00FF) as u8;
        }
        if hi_index < dest.len() {
            dest[hi_index] ^= (product >> 8) as u8;
        }
    }
}

struct CoeffTable {
    lo: [u16; 256],
    hi: [u16; 256],
}

impl CoeffTable {
    fn new(coeff: u16) -> Self {
        let mut lo = [0u16; 256];
        let mut hi = [0u16; 256];
        for value in 0..256usize {
            lo[value] = gf65536_mul(value as u16, coeff);
            hi[value] = gf65536_mul((value as u16) << 8, coeff);
        }
        Self { lo, hi }
    }

    fn mul(&self, value: u16) -> u16 {
        self.lo[(value & 0x00FF) as usize] ^ self.hi[(value >> 8) as usize]
    }
}

pub fn gf65536_add_bytes(dest: &mut [u8], src: &[u8]) {
    for (dst, src) in dest.iter_mut().zip(src.iter().copied()) {
        *dst ^= src;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FIELD_ORDER, gf65536_inv, gf65536_mul, gf65536_mul_add_bytes, gf65536_mul_bytes,
        gf65536_mul_slow, gf65536_pow, gf65536_add_bytes,
    };

    #[test]
    fn gf65536_inverse_roundtrips_nonzero_values() {
        for value in [1u16, 2, 3, 5, 17, 257, 4097, 0xBEEF, 0xFFFF] {
            assert_eq!(gf65536_mul(value, gf65536_inv(value)), 1);
            assert_eq!(
                gf65536_inv(value),
                gf65536_pow(value, (FIELD_ORDER - 1) as u32)
            );
        }
    }

    #[test]
    fn gf65536_table_multiply_matches_bit_serial_reference() {
        for a in [0u16, 1, 2, 3, 17, 257, 4097, 0xBEEF, 0xFFFF] {
            for b in [0u16, 1, 2, 5, 19, 513, 8191, 0xCAFE, 0xFFFF] {
                assert_eq!(gf65536_mul(a, b), gf65536_mul_slow(a, b));
            }
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

    #[test]
    fn gf65536_byte_multiply_matches_scalar_lanes() {
        let data = [0x34, 0x12, 0xFE, 0xCA, 0x77, 0x41, 0x00];
        let coeff = 0xD321;
        let encoded = gf65536_mul_bytes(&data, coeff, data.len());
        for lane in 0..data.len().div_ceil(2) {
            let lo_index = lane * 2;
            let hi_index = lo_index + 1;
            let input = data[lo_index] as u16
                | ((data.get(hi_index).copied().unwrap_or(0) as u16) << 8);
            let expected = gf65536_mul(input, coeff);
            assert_eq!(encoded[lo_index], (expected & 0x00FF) as u8);
            if hi_index < data.len() {
                assert_eq!(encoded[hi_index], (expected >> 8) as u8);
            }
        }
    }

    #[test]
    fn gf65536_mul_add_matches_mul_then_xor() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55];
        let coeff = 0xA51F;
        let mut dest = [0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5];
        let mut expected = dest;
        let product = gf65536_mul_bytes(&data, coeff, dest.len());
        gf65536_add_bytes(&mut expected, &product);
        gf65536_mul_add_bytes(&mut dest, &data, coeff);
        assert_eq!(dest, expected);
    }
}
