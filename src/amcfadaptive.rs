use crate::amcfspatial::{
    AMCF_PHASE_ANCHOR, AMCF_PHASE_FANOUT, amcf_outer_target_degree_floor, amcf_spatial_plan,
    amcf_spatial_sparse_positions,
};
use crate::gf256::gf_pow;

pub const AMCF_PHASE_OUTER: &str = "amcf-outer";
pub const AMCF_PHASE_MICRO: &str = "amcf-micro";
pub const AMCF_MICRO_MAX_ROWS: usize = 6;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmcfPlan {
    pub body_row_count: usize,
    pub outer_row_count: usize,
    pub outer_target_sizes: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmcfRowStructure {
    pub row_id: usize,
    pub phase: &'static str,
    pub target_size: usize,
    pub positions: Vec<usize>,
}

pub fn amcf_plan(n: usize, row_count: usize) -> AmcfPlan {
    if n == 0 || row_count == 0 {
        return AmcfPlan {
            body_row_count: 0,
            outer_row_count: 0,
            outer_target_sizes: Vec::new(),
        };
    }
    if row_count == 1 {
        let target = n.min(1usize.max(((2 * n) as f64 / 3.0).ceil() as usize));
        return AmcfPlan {
            body_row_count: 0,
            outer_row_count: 1,
            outer_target_sizes: vec![target],
        };
    }
    if row_count <= AMCF_MICRO_MAX_ROWS {
        return AmcfPlan {
            body_row_count: 0,
            outer_row_count: row_count,
            outer_target_sizes: vec![n; row_count],
        };
    }

    let mut outer_row_count = if row_count <= 8 && n <= 48 {
        2usize.min(row_count - 1)
    } else {
        3usize.min(1usize.max(row_count / 8))
    };
    let mut body_row_count = row_count - outer_row_count;
    if body_row_count == 0 {
        body_row_count = 1;
        outer_row_count = row_count - body_row_count;
    }
    let base_degree = amcf_outer_target_degree_floor(n);
    let outer_target_sizes = match outer_row_count {
        1 => vec![n.min(base_degree.max(((2 * n) as f64 / 3.0).ceil() as usize))],
        2 => vec![
            n.min(base_degree.max((n as f64 / 2.0).ceil() as usize)),
            n.min(base_degree.max(((2 * n) as f64 / 3.0).ceil() as usize)),
        ],
        _ => vec![
            n.min(base_degree.max((n as f64 / 3.0).ceil() as usize)),
            n.min(base_degree.max((n as f64 / 2.0).ceil() as usize)),
            n.min(base_degree.max(((2 * n) as f64 / 3.0).ceil() as usize)),
        ],
    };
    AmcfPlan {
        body_row_count,
        outer_row_count,
        outer_target_sizes,
    }
}

pub fn amcf_phase_for_row(
    n: usize,
    row_count: usize,
    row_id: usize,
) -> Result<&'static str, String> {
    let plan = amcf_plan(n, row_count);
    if row_id >= row_count {
        return Err("row_id out of range for AMCF phase lookup".into());
    }
    if row_count <= AMCF_MICRO_MAX_ROWS {
        return Ok(AMCF_PHASE_MICRO);
    }
    if row_id < plan.body_row_count {
        let body_plan = amcf_spatial_plan(n, 1usize.max(plan.body_row_count));
        return Ok(if row_id < body_plan.phase1_rows {
            AMCF_PHASE_ANCHOR
        } else {
            AMCF_PHASE_FANOUT
        });
    }
    Ok(AMCF_PHASE_OUTER)
}

pub fn amcf_positions(
    _seed_base: &[u8],
    row_id: usize,
    n: usize,
    row_count: usize,
) -> Result<Vec<usize>, String> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if row_count == 0 {
        return Err("row_count must be positive for AMCF row generation".into());
    }
    if row_id >= row_count {
        return Err("row_id out of range for AMCF row generation".into());
    }
    if row_count <= AMCF_MICRO_MAX_ROWS {
        return Ok((0..n).collect());
    }
    let plan = amcf_plan(n, row_count);
    if row_id < plan.body_row_count {
        return amcf_spatial_sparse_positions(row_id, n, plan.body_row_count);
    }
    let outer_index = row_id - plan.body_row_count;
    balanced_outer_positions(n, outer_index, row_id, plan.outer_target_sizes[outer_index])
}

pub fn amcf_row_structure(
    seed_base: &[u8],
    row_id: usize,
    n: usize,
    row_count: usize,
) -> Result<AmcfRowStructure, String> {
    let positions = amcf_positions(seed_base, row_id, n, row_count)?;
    let phase = amcf_phase_for_row(n, row_count, row_id)?;
    let plan = amcf_plan(n, row_count);
    let target_size = if row_count <= AMCF_MICRO_MAX_ROWS {
        n
    } else if row_id < plan.body_row_count {
        positions.len()
    } else {
        plan.outer_target_sizes[row_id - plan.body_row_count]
    };
    Ok(AmcfRowStructure {
        row_id,
        phase,
        target_size,
        positions,
    })
}

pub fn sample_amcf_combination(
    seed_base: &[u8],
    seed_id: usize,
    data_indices: &[usize],
    row_count: usize,
) -> Result<Vec<(usize, u8)>, String> {
    if data_indices.is_empty() {
        return Ok(Vec::new());
    }
    if row_count == 0 {
        return Err("row_count must be positive for AMCF sampling".into());
    }
    if row_count <= AMCF_MICRO_MAX_ROWS {
        return micro_vandermonde_combination(seed_id, data_indices);
    }
    let positions = amcf_positions(seed_base, seed_id, data_indices.len(), row_count)?;
    Ok(positions
        .into_iter()
        .enumerate()
        .map(|(ordinal, pos)| {
            (
                data_indices[pos],
                amcf_position_coefficient(seed_id, ordinal, pos)
                    .expect("AMCF coefficient generation must be non-zero"),
            )
        })
        .collect())
}

fn balanced_outer_positions(
    n: usize,
    outer_index: usize,
    row_id: usize,
    target_size: usize,
) -> Result<Vec<usize>, String> {
    if target_size == 0 || target_size > n {
        return Err("target_size must be in 1..n for AMCF outer rows".into());
    }
    let offset = (outer_index * 1usize.max(n / 7) + row_id * 1usize.max(n / 19)) % n;
    let mut positions: Vec<usize> = (0..target_size)
        .map(|index| (offset + ((index * n) / target_size)) % n)
        .collect();
    positions.sort_unstable();
    positions.dedup();
    if positions.len() != target_size {
        return Err("Balanced AMCF outer placement produced duplicate positions".into());
    }
    Ok(positions)
}

fn micro_vandermonde_combination(
    seed_id: usize,
    data_indices: &[usize],
) -> Result<Vec<(usize, u8)>, String> {
    if data_indices.len() > 255 {
        return Err(format!(
            "AMCF micro regime requires at most 255 data symbols, got {}",
            data_indices.len()
        ));
    }
    let exponent = seed_id as u32;
    let mut combo = Vec::with_capacity(data_indices.len());
    for (position, data_index) in data_indices.iter().copied().enumerate() {
        let coeff = gf_pow((position + 1) as u8, exponent);
        if coeff == 0 {
            return Err("AMCF micro coefficient generation produced zero".into());
        }
        combo.push((data_index, coeff));
    }
    Ok(combo)
}

fn amcf_position_coefficient(row_id: usize, ordinal: usize, position: usize) -> Result<u8, String> {
    let base = (((position + row_id + ordinal) % 255) + 1) as u8;
    let exponent = (1 + ((row_id + ordinal) % 11)) as u32;
    let coeff = gf_pow(base, exponent);
    if coeff == 0 {
        return Err("AMCF coefficient generation produced zero".into());
    }
    Ok(coeff)
}
