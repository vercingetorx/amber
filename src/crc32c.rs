const POLY: u32 = 0x1EDC6F41;

const fn make_table() -> [u32; 256] {
    let mut tbl = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut bit = 0;
        while bit < 8 {
            if (c & 1) != 0 {
                c = (c >> 1) ^ POLY;
            } else {
                c >>= 1;
            }
            bit += 1;
        }
        tbl[n] = c;
        n += 1;
    }
    tbl
}

const TABLE: [u32; 256] = make_table();

pub fn crc32c(data: &[u8], crc: u32) -> u32 {
    let mut c = !crc;
    for &byte in data {
        c = TABLE[((c ^ (byte as u32)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
#[path = "tests/crc32c.rs"]
mod tests;
