const POLY_REDUCED: u8 = 0x1B;

pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut res = 0u8;
    while b != 0 {
        if (b & 1) != 0 {
            res ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= POLY_REDUCED;
        }
        b >>= 1;
    }
    res
}

pub fn gf_pow(a: u8, power: u32) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut power = power;
    while power != 0 {
        if (power & 1) != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        power >>= 1;
    }
    result
}

pub fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("No inverse for zero in GF(256)");
    }
    gf_pow(a, 254)
}

pub fn gf_mul_bytes(data: &[u8], coeff: u8) -> Vec<u8> {
    match coeff {
        0 => vec![0u8; data.len()],
        1 => data.to_vec(),
        _ => data.iter().map(|&byte| gf_mul(byte, coeff)).collect(),
    }
}

pub fn gf_add_bytes(dest: &mut [u8], src: &[u8]) {
    for (dst, src) in dest.iter_mut().zip(src.iter().copied()) {
        *dst ^= src;
    }
}
