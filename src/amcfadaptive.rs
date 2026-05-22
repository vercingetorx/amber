use std::collections::BTreeSet;

use crate::amcfspatial::{
    AMCF_PHASE_ANCHOR, AMCF_PHASE_FANOUT, amcf_outer_target_degree_floor, amcf_spatial_plan,
};
use crate::coprime::coprime_from_start;
use crate::gf256::{gf_inv, gf_pow};

pub const AMCF_PHASE_OUTER: &str = "amcf-outer";
pub const AMCF_PHASE_MICRO: &str = "amcf-micro";
pub const AMCF_MICRO_MAX_ROWS: usize = 6;
const AMCF_DENSE_MAX_ROWS: usize = AMCF_OUTER_FRACTIONS.len();

const AMCF_OUTER_FRACTIONS: &[(usize, usize)] = &[
    (5, 8),
    (21, 32),
    (21, 32),
    (21, 32),
    (21, 32),
    (21, 32),
    (2, 3),
    (11, 16),
];
const AMCF_BRIDGE_QUOTA: usize = 6;
const AMCF_BRIDGE_LANE_COUNT: usize = 8;

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
    if row_count <= AMCF_DENSE_MAX_ROWS {
        return AmcfPlan {
            body_row_count: 0,
            outer_row_count: row_count,
            outer_target_sizes: vec![n; row_count],
        };
    }
    let outer_target_sizes = amcf_outer_target_sizes(n);
    let outer_row_count = outer_target_sizes.len();
    AmcfPlan {
        body_row_count: row_count.saturating_sub(outer_row_count),
        outer_row_count,
        outer_target_sizes,
    }
}

pub fn amcf_phase_for_row(
    n: usize,
    row_count: usize,
    row_id: usize,
) -> Result<&'static str, String> {
    if row_id >= row_count {
        return Err("row_id out of range for AMCF phase lookup".into());
    }
    if row_count <= AMCF_DENSE_MAX_ROWS {
        return Ok(AMCF_PHASE_MICRO);
    }
    let plan = amcf_plan(n, row_count);
    if row_id < plan.body_row_count {
        let body_plan = amcf_spatial_plan(n, plan.body_row_count.max(1));
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
    Ok(amcf_positions_by_row(n, row_count)?[row_id].clone())
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
    let target_size = if row_count <= AMCF_MICRO_MAX_ROWS || row_id < plan.body_row_count {
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
    _seed_base: &[u8],
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
    if row_count <= AMCF_DENSE_MAX_ROWS {
        return dense_amcf_combination(seed_id, data_indices);
    }
    if seed_id >= row_count {
        return Err("seed_id out of range for AMCF sampling".into());
    }
    let rows = amcf_combinations_by_row(data_indices, row_count)?;
    Ok(rows[seed_id].clone())
}

fn amcf_outer_target_sizes(n: usize) -> Vec<usize> {
    let floor = amcf_outer_target_degree_floor(n);
    AMCF_OUTER_FRACTIONS
        .iter()
        .map(|(numerator, denominator)| {
            n.min(floor.max((numerator * n).div_ceil(*denominator)))
        })
        .collect()
}

fn amcf_positions_by_row(n: usize, row_count: usize) -> Result<Vec<Vec<usize>>, String> {
    if n == 0 {
        return Ok(vec![Vec::new(); row_count]);
    }
    if row_count == 0 {
        return Err("row_count must be positive for AMCF row generation".into());
    }
    if row_count <= AMCF_DENSE_MAX_ROWS {
        return Ok((0..row_count).map(|_| (0..n).collect()).collect());
    }

    let outer_targets = amcf_outer_target_sizes(n);
    let outer_count = outer_targets.len();
    if row_count <= outer_count {
        return Err("AMCF requires more rows than its outer row count".into());
    }
    let body_count = row_count - outer_count;
    let mut rows = Vec::with_capacity(row_count);
    for row_id in 0..row_count {
        if row_id < body_count {
            rows.push(amcf_body_positions(row_id, n, body_count)?);
        } else {
            let outer_index = row_id - body_count;
            rows.push(balanced_outer_positions(
                n,
                outer_index,
                row_id,
                outer_targets[outer_index],
            )?);
        }
    }
    Ok(rows)
}

fn amcf_body_positions(row_id: usize, n: usize, body_count: usize) -> Result<Vec<usize>, String> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if body_count == 0 {
        return Err("body_count must be positive for AMCF row generation".into());
    }
    if row_id >= body_count {
        return Err("row_id out of range for AMCF row generation".into());
    }

    let target = n.min(amcf_spatial_plan(n, body_count).degree.max(1));
    let root = (n as f64).sqrt().round() as usize;
    let unit_size = 1usize.max((target * 2).max(n.div_ceil(root.max(1))));
    let unit_count = 1usize.max(n.div_ceil(unit_size));
    let home_unit = row_id % unit_count;
    let local_start = home_unit * unit_size;
    let local_span = 1usize.max(unit_size.min(n - local_start));
    let coverage_quota = target.min(n.div_ceil(body_count));
    let local_quota = (target - coverage_quota).min(1usize.max(target.div_ceil(4)));
    let bridge_quota = (target - coverage_quota - local_quota).min(AMCF_BRIDGE_QUOTA);
    let neighbor_quota = (target - coverage_quota - local_quota)
        .min(2usize.max(target.div_ceil(2)))
        .saturating_sub(bridge_quota);

    let mut seen = BTreeSet::new();
    let mut positions = Vec::with_capacity(target);

    for pos in (row_id % body_count..n).step_by(body_count) {
        append_position(&mut positions, &mut seen, pos, n, target);
        if positions.len() >= coverage_quota {
            break;
        }
    }

    let lane_count = 2usize.max(4usize.min((local_span as f64).sqrt().ceil() as usize));
    let lane = row_id % lane_count;
    let local_step = coprime_from_start(1 + row_id + target, local_span);
    for ordinal in 0..local_span {
        let offset = (lane + ordinal * local_step) % local_span;
        append_position(
            &mut positions,
            &mut seen,
            local_start + offset,
            n,
            target,
        );
        if positions.len() >= coverage_quota + local_quota {
            break;
        }
    }

    let bridge_goal = coverage_quota + local_quota + bridge_quota;
    append_bridge_positions(
        &mut positions,
        &mut seen,
        BridgePlacement {
            n,
            target,
            row_id,
            body_count,
            unit_size,
            home_unit,
            goal: bridge_goal,
        },
    );

    let neighbor_goal = bridge_goal + neighbor_quota;
    let neighbor_step = coprime_from_start(1 + row_id * 2 + target, unit_count.max(1));
    let mut arm = 0usize;
    while positions.len() < neighbor_goal && arm < unit_count.max(1) * 2 {
        let direction = if arm.is_multiple_of(2) { -1isize } else { 1isize };
        let distance = 1 + ((arm / 2) * neighbor_step) % unit_count.max(1);
        let target_unit = ((home_unit as isize + direction * distance as isize)
            .rem_euclid(unit_count as isize)) as usize;
        let start = target_unit * unit_size;
        let span = 1usize.max(unit_size.min(n - start));
        let intra_step = coprime_from_start(1 + row_id + arm + target, span);
        let offset = (row_id * 3 + arm * 5) % span;
        append_position(
            &mut positions,
            &mut seen,
            start + offset * intra_step,
            n,
            target,
        );
        arm += 1;
    }

    let global_step = coprime_from_start(1 + row_id * 2 + target * 3, n);
    let global_offset = ((row_id * n) / body_count + row_id * row_id + target) % n;
    for ordinal in 0..n {
        append_position(
            &mut positions,
            &mut seen,
            global_offset + ordinal * global_step,
            n,
            target,
        );
        if positions.len() >= target {
            break;
        }
    }

    if positions.len() != target {
        return Err("AMCF placement failed".into());
    }
    positions.sort_unstable();
    Ok(positions)
}

struct BridgePlacement {
    n: usize,
    target: usize,
    row_id: usize,
    body_count: usize,
    unit_size: usize,
    home_unit: usize,
    goal: usize,
}

fn append_bridge_positions(
    positions: &mut Vec<usize>,
    seen: &mut BTreeSet<usize>,
    placement: BridgePlacement,
) {
    let phase = placement.row_id / 2;
    let mut lane = placement.row_id % AMCF_BRIDGE_LANE_COUNT;
    let mut attempts = 0usize;
    while positions.len() < placement.goal && attempts < AMCF_BRIDGE_LANE_COUNT * 4 {
        let lo = (lane * placement.n) / AMCF_BRIDGE_LANE_COUNT;
        let hi = ((lane + 1) * placement.n) / AMCF_BRIDGE_LANE_COUNT;
        let width = 1usize.max(hi - lo);
        let slope = coprime_from_start(
            1 + phase * 6 + placement.target * 5 + placement.body_count,
            placement.n.max(1),
        );
        let offset = (phase * phase
            + slope * lane
            + attempts * (2 * placement.row_id + 1)
            + 17 * placement.target)
            % width;
        let candidate = placement.n - 1 - (lo + offset);
        let unit_count = placement.n.div_ceil(placement.unit_size).saturating_sub(1);
        let candidate_unit = (candidate / placement.unit_size).min(unit_count);
        if candidate_unit != placement.home_unit || attempts >= AMCF_BRIDGE_LANE_COUNT {
            append_position(positions, seen, candidate, placement.n, placement.target);
        }
        lane = (lane + 1) % AMCF_BRIDGE_LANE_COUNT;
        attempts += 1;
    }
}

fn append_position(
    positions: &mut Vec<usize>,
    seen: &mut BTreeSet<usize>,
    idx: usize,
    n: usize,
    target: usize,
) {
    if positions.len() >= target {
        return;
    }
    let candidate = idx % n;
    if seen.insert(candidate) {
        positions.push(candidate);
    }
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

fn dense_amcf_combination(seed_id: usize, data_indices: &[usize]) -> Result<Vec<(usize, u8)>, String> {
    data_indices
        .iter()
        .copied()
        .enumerate()
        .map(|(position, data_index)| {
            amcf_position_coefficient(seed_id, position, position)
                .map(|coefficient| (data_index, coefficient))
        })
        .collect()
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

fn amcf_combinations_by_row(
    data_indices: &[usize],
    row_count: usize,
) -> Result<Vec<Vec<(usize, u8)>>, String> {
    let positions_by_row = amcf_positions_by_row(data_indices.len(), row_count)?;
    let mut rows = Vec::with_capacity(row_count);
    let use_cauchy_coefficients = data_indices.len() + row_count <= 256;

    for (row_id, positions) in positions_by_row.iter().enumerate() {
        if row_count <= AMCF_MICRO_MAX_ROWS {
            let row = micro_vandermonde_combination(row_id, data_indices)?;
            rows.push(row);
            continue;
        }
        let coefficients = if use_cauchy_coefficients {
            positions
                .iter()
                .copied()
                .map(|position| cauchy_position_coefficient(row_id, position, data_indices.len()))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            positions
                .iter()
                .copied()
                .enumerate()
                .map(|(ordinal, position)| amcf_position_coefficient(row_id, ordinal, position))
                .collect::<Result<Vec<_>, _>>()?
        };
        let row = positions
            .iter()
            .copied()
            .zip(coefficients.iter().copied())
            .map(|(position, coefficient)| (data_indices[position], coefficient))
            .collect::<Vec<_>>();
        rows.push(row);
    }
    Ok(rows)
}

fn cauchy_position_coefficient(
    row_id: usize,
    position: usize,
    data_count: usize,
) -> Result<u8, String> {
    let row_tag = data_count + row_id;
    if row_tag > 255 || position > 255 {
        return Err("AMCF Cauchy coefficient tags exceed GF(256)".into());
    }
    let denominator = (row_tag as u8) ^ (position as u8);
    if denominator == 0 {
        return Err("AMCF Cauchy coefficient generation produced zero denominator".into());
    }
    Ok(gf_inv(denominator))
}

#[cfg(test)]
#[path = "tests/amcfadaptive.rs"]
mod tests;
