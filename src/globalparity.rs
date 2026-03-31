use crate::amcfadaptive::sample_amcf_combination;

pub const GLOBAL_PARITY_SCHEME_AMCF: &str = "amcf";
pub const MIN_TOTAL_PARITY_ROWS_FLOOR: usize = 6;
pub const CANONICAL_ARCHIVAL_GLOBAL_EPSILON_PPM: usize = 170_000;
pub const CANONICAL_ARCHIVAL_LOCAL_EQUIVALENT_K: usize = 12;

pub fn validate_global_parity_scheme(scheme: &str) -> Result<&'static str, String> {
    let normalized = scheme.trim().to_ascii_lowercase();
    if normalized != GLOBAL_PARITY_SCHEME_AMCF {
        return Err(format!("Unsupported global parity scheme: {scheme}"));
    }
    Ok(GLOBAL_PARITY_SCHEME_AMCF)
}

pub fn require_canonical_global_parity_scheme(scheme: &str) -> Result<&'static str, String> {
    validate_global_parity_scheme(scheme)
}

pub fn canonical_total_parity_rows(data_count: usize) -> Result<usize, String> {
    if data_count == 0 {
        return Ok(0);
    }
    let global_rows = (if data_count >= 2 { 2 } else { 1 })
        .max((data_count * CANONICAL_ARCHIVAL_GLOBAL_EPSILON_PPM) / 1_000_000);
    let local_equivalent_rows = data_count.div_ceil(CANONICAL_ARCHIVAL_LOCAL_EQUIVALENT_K);
    Ok(MIN_TOTAL_PARITY_ROWS_FLOOR.max(local_equivalent_rows + global_rows))
}

pub fn canonical_global_parity_rows(data_count: usize) -> Result<usize, String> {
    canonical_total_parity_rows(data_count)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericGlobalParitySampler {
    pub scheme: &'static str,
    pub seed_base: [u8; 16],
    pub data_indices: Vec<usize>,
    pub row_count: usize,
}

impl GenericGlobalParitySampler {
    pub fn new(
        scheme: &str,
        seed_base: [u8; 16],
        data_indices: Vec<usize>,
        row_count: usize,
    ) -> Result<Self, String> {
        let scheme = validate_global_parity_scheme(scheme)?;
        if row_count == 0 {
            return Err("row_count must be positive for global parity sampling".into());
        }
        Ok(Self {
            scheme,
            seed_base,
            data_indices,
            row_count,
        })
    }

    pub fn combination(&self, seed_id: usize) -> Result<Vec<(usize, u8)>, String> {
        sample_amcf_combination(&self.seed_base, seed_id, &self.data_indices, self.row_count)
    }
}
