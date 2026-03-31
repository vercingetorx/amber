use crate::coprime::coprime_from_start;

pub const AMCF_PHASE_ANCHOR: &str = "amcf-anchor";
pub const AMCF_PHASE_FANOUT: &str = "amcf-fanout";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmcfSpatialPlan {
    pub degree: usize,
    pub coverage_quota: usize,
    pub unit_size: usize,
    pub unit_count: usize,
    pub phase1_rows: usize,
    pub lane_count: usize,
}

pub fn amcf_spatial_target_degree(n: usize, seed_id: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut base = 6usize.max(ceil_log2(2usize.max(n)) + 1);
    if seed_id % 4 == 3 {
        base += 1;
    }
    n.min(base)
}

pub fn amcf_outer_target_degree_floor(n: usize) -> usize {
    amcf_spatial_target_degree(n, 0)
}

pub fn amcf_spatial_plan(n: usize, row_count: usize) -> AmcfSpatialPlan {
    if n == 0 || row_count == 0 {
        return AmcfSpatialPlan {
            degree: 0,
            coverage_quota: 0,
            unit_size: 0,
            unit_count: 0,
            phase1_rows: 0,
            lane_count: 0,
        };
    }
    let mut base_degree = amcf_spatial_target_degree(n, 0);
    if n >= 128 && row_count >= 24 {
        let root = (n as f64).sqrt();
        base_degree = base_degree.max(n.min(24usize.max((root * 1.5).ceil() as usize)));
    }
    let coverage_quota = n.div_ceil(row_count);
    let degree = base_degree.max(n.min(coverage_quota + 2usize.max(base_degree.div_ceil(3))));
    let unit_size = (degree * 2).max(n.div_ceil(4usize.max((n as f64).sqrt().round() as usize)));
    let unit_count = 1usize.max(n.div_ceil(unit_size));
    let lane_count = 2usize;
    let target_phase1_rows = 1usize.max((row_count as f64 * 0.5).ceil() as usize);
    let coverage_rows = unit_count * lane_count;
    let phase1_rows = if row_count == 1 {
        1
    } else {
        (row_count - 1).min(target_phase1_rows.max(coverage_rows))
    };
    AmcfSpatialPlan {
        degree,
        coverage_quota,
        unit_size,
        unit_count,
        phase1_rows,
        lane_count,
    }
}

pub fn amcf_spatial_sparse_positions(
    row_id: usize,
    n: usize,
    row_count: usize,
) -> Result<Vec<usize>, String> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if row_count == 0 {
        return Err("row_count must be positive for AMCF spatial row generation".into());
    }
    if row_id >= row_count {
        return Err("row_id out of range for AMCF spatial row generation".into());
    }
    let plan = amcf_spatial_plan(n, row_count);
    let degree = plan.degree;
    let home = row_id % plan.unit_count;
    let local_start = home * plan.unit_size;
    let local_span = 1usize.max((n - local_start).min(plan.unit_size));
    let mut seen = std::collections::BTreeSet::new();
    let mut positions = Vec::new();

    if row_id < plan.phase1_rows {
        let coverage_target = degree.min(n).min(plan.coverage_quota);
        append_coverage_sweep(
            &mut positions,
            &mut seen,
            n,
            row_id,
            row_count,
            coverage_target,
        )?;
        let local_target = degree
            .min(n)
            .min(coverage_target + local_span.min(1usize.max(degree.div_ceil(3))));
        let lane = row_id / plan.unit_count;
        let mut offset = lane;
        while offset < local_span {
            append_unique_index(&mut positions, &mut seen, local_start + offset, n);
            if positions.len() >= local_target {
                break;
            }
            offset += plan.lane_count;
        }
        if positions.len() < local_target {
            for offset in 0..local_span {
                append_unique_index(&mut positions, &mut seen, local_start + offset, n);
                if positions.len() >= local_target {
                    break;
                }
            }
        }
        if positions.len() < degree.min(n) {
            let remaining = degree.min(n) - positions.len();
            let back_count = remaining.div_ceil(2);
            let fwd_count = remaining - back_count;
            neighbor_positions_distances(
                &mut positions,
                &mut seen,
                home,
                plan.unit_count,
                plan.unit_size,
                n,
                row_id,
                &(0..back_count).map(|i| 1 + i).collect::<Vec<_>>(),
                -1,
            );
            neighbor_positions_distances(
                &mut positions,
                &mut seen,
                home,
                plan.unit_count,
                plan.unit_size,
                n,
                row_id,
                &(0..fwd_count).map(|i| 1 + i).collect::<Vec<_>>(),
                1,
            );
        }
        fill_positions(&mut positions, &mut seen, n, degree, row_id);
        return Ok(positions);
    }

    let coverage_target = degree.min(n).min(plan.coverage_quota);
    append_coverage_sweep(
        &mut positions,
        &mut seen,
        n,
        row_id,
        row_count,
        coverage_target,
    )?;
    let local_count = local_span.min(2usize.max((degree - coverage_target).div_ceil(2)));
    let local_step = coprime_from_start(1 + row_id, local_span);
    let local_offset = (row_id * 3 + 1) % local_span;
    for j in 0..local_count {
        let pos = local_start + ((local_offset + j * local_step) % local_span);
        append_unique_index(&mut positions, &mut seen, pos, n);
    }
    let remaining = degree.min(n).saturating_sub(positions.len());
    let back_count = remaining.div_ceil(2);
    let fwd_count = remaining - back_count;
    neighbor_positions_distances(
        &mut positions,
        &mut seen,
        home,
        plan.unit_count,
        plan.unit_size,
        n,
        row_id,
        &(0..back_count).map(|i| 1 + (i * 2)).collect::<Vec<_>>(),
        -1,
    );
    neighbor_positions_distances(
        &mut positions,
        &mut seen,
        home,
        plan.unit_count,
        plan.unit_size,
        n,
        row_id,
        &(0..fwd_count).map(|i| 1 + (i * 2)).collect::<Vec<_>>(),
        1,
    );
    fill_positions(&mut positions, &mut seen, n, degree, row_id);
    Ok(positions)
}

fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    usize::BITS as usize - (n - 1).leading_zeros() as usize
}

fn append_unique_index(
    positions: &mut Vec<usize>,
    seen: &mut std::collections::BTreeSet<usize>,
    idx: usize,
    n: usize,
) {
    let candidate = idx % n;
    if seen.insert(candidate) {
        positions.push(candidate);
    }
}

fn fill_positions(
    positions: &mut Vec<usize>,
    seen: &mut std::collections::BTreeSet<usize>,
    n: usize,
    degree: usize,
    row_id: usize,
) {
    if positions.len() >= degree.min(n) {
        positions.sort_unstable();
        return;
    }
    let step = coprime_from_start(1 + row_id * 2 + degree, n);
    let start = (row_id * 1usize.max(n / 1usize.max(degree))) % n;
    for offset in 0..n {
        let candidate = (start + offset * step) % n;
        if seen.insert(candidate) {
            positions.push(candidate);
        }
        if positions.len() >= degree.min(n) {
            break;
        }
    }
    positions.sort_unstable();
}

fn neighbor_positions_distances(
    positions: &mut Vec<usize>,
    seen: &mut std::collections::BTreeSet<usize>,
    home: usize,
    unit_count: usize,
    unit_size: usize,
    n: usize,
    row_id: usize,
    distances: &[usize],
    direction: isize,
) {
    for (arm_index, step_out) in distances.iter().copied().enumerate() {
        let mut target_unit = home as isize + (step_out as isize * direction);
        if target_unit < 0 || target_unit >= unit_count as isize {
            let fallback = home as isize + direction;
            target_unit = if fallback >= 0 && fallback < unit_count as isize {
                fallback
            } else {
                home as isize
            };
        }
        let target_unit = target_unit as usize;
        let start = target_unit * unit_size;
        let span = 1usize.max(unit_size.min(n - start));
        let step = coprime_from_start(1 + row_id + target_unit + arm_index, span);
        let offset = (row_id * 3 + target_unit + arm_index * 5) % span;
        let pos = start + ((offset + step) % span);
        append_unique_index(positions, seen, pos, n);
    }
}

fn append_coverage_sweep(
    positions: &mut Vec<usize>,
    seen: &mut std::collections::BTreeSet<usize>,
    n: usize,
    row_id: usize,
    row_count: usize,
    target_size: usize,
) -> Result<(), String> {
    if row_count == 0 {
        return Err("row_count must be positive for AMCF spatial coverage sweep".into());
    }
    let mut offset = row_id % row_count;
    while offset < n {
        append_unique_index(positions, seen, offset, n);
        if positions.len() >= target_size {
            return Ok(());
        }
        offset += row_count;
    }
    Ok(())
}
