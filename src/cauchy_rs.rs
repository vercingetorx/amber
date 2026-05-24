use crate::gf65536::gf65536_inv;

pub const CAUCHY_RS_SCHEME_NAME: &str = "cauchy-rs";
pub const GF65536_TAG_SPACE: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CauchyRsSampler {
    pub data_indices: Vec<usize>,
    pub row_count: usize,
}

impl CauchyRsSampler {
    pub fn new(data_indices: Vec<usize>, row_count: usize) -> Result<Self, String> {
        if row_count == 0 {
            return Err("row_count must be positive for Cauchy RS sampling".into());
        }
        validate_cauchy_rs_dimensions(data_indices.len(), row_count)?;
        Ok(Self {
            data_indices,
            row_count,
        })
    }

    pub fn combination(&self, row_id: usize) -> Result<Vec<(usize, u16)>, String> {
        sample_cauchy_rs_combination(row_id, &self.data_indices, self.row_count)
    }
}

pub fn validate_cauchy_rs_dimensions(data_count: usize, row_count: usize) -> Result<(), String> {
    if data_count == 0 {
        return Ok(());
    }
    if data_count + row_count > GF65536_TAG_SPACE {
        return Err(format!(
            "global GF(2^16) Cauchy Reed-Solomon requires data symbols + repair rows <= {GF65536_TAG_SPACE}; got {} + {}",
            data_count, row_count
        ));
    }
    Ok(())
}

pub fn sample_cauchy_rs_combination(
    row_id: usize,
    data_indices: &[usize],
    row_count: usize,
) -> Result<Vec<(usize, u16)>, String> {
    if data_indices.is_empty() {
        return Ok(Vec::new());
    }
    validate_cauchy_rs_dimensions(data_indices.len(), row_count)?;
    if row_id >= row_count {
        return Err("row_id out of range for Cauchy RS sampling".into());
    }

    let row_tag = data_indices.len() + row_id;
    data_indices
        .iter()
        .enumerate()
        .map(|(position, symbol_index)| {
            let denominator = (row_tag ^ position) as u16;
            if denominator == 0 {
                return Err("Cauchy RS row and column tags collided".into());
            }
            Ok((*symbol_index, gf65536_inv(denominator)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::gf65536::{gf65536_inv, gf65536_mul};

    use super::{GF65536_TAG_SPACE, sample_cauchy_rs_combination, validate_cauchy_rs_dimensions};

    #[test]
    fn cauchy_rs_rejects_sets_larger_than_gf65536_tag_space() {
        let err = validate_cauchy_rs_dimensions(GF65536_TAG_SPACE, 1).unwrap_err();
        assert!(err.contains("data symbols + repair rows"));
    }

    #[test]
    fn cauchy_rs_rows_are_dense_and_nonzero() {
        let data_indices = (0..236).collect::<Vec<_>>();
        for row_id in 0..40 {
            let row = sample_cauchy_rs_combination(row_id, &data_indices, 40).unwrap();
            assert_eq!(row.len(), data_indices.len());
            assert!(row.iter().all(|(_, coeff)| *coeff != 0));
            assert_eq!(row[0].0, 0);
            assert_eq!(row[235].0, 235);
        }
    }

    #[test]
    fn small_cauchy_matrix_has_full_rank_for_every_square_minor() {
        let data_indices = (0..8).collect::<Vec<_>>();
        let rows = (0..5)
            .map(|row_id| {
                sample_cauchy_rs_combination(row_id, &data_indices, 5)
                    .unwrap()
                    .into_iter()
                    .collect::<BTreeMap<_, _>>()
            })
            .collect::<Vec<_>>();

        for size in 1..=5 {
            for row_set in combinations(5, size) {
                for col_set in combinations(8, size) {
                    let matrix = row_set
                        .iter()
                        .map(|row| {
                            col_set
                                .iter()
                                .map(|col| rows[*row][col])
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(rank(matrix), size);
                }
            }
        }
    }

    fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
        fn go(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
            if cur.len() == k {
                out.push(cur.clone());
                return;
            }
            for value in start..n {
                cur.push(value);
                go(value + 1, n, k, cur, out);
                cur.pop();
            }
        }
        let mut out = Vec::new();
        go(0, n, k, &mut Vec::new(), &mut out);
        out
    }

    fn rank(mut matrix: Vec<Vec<u16>>) -> usize {
        if matrix.is_empty() {
            return 0;
        }
        let rows = matrix.len();
        let cols = matrix[0].len();
        let mut rank = 0usize;
        for col in 0..cols {
            let pivot = (rank..rows).find(|row| matrix[*row][col] != 0);
            let Some(pivot) = pivot else {
                continue;
            };
            matrix.swap(rank, pivot);
            let inv = gf65536_inv(matrix[rank][col]);
            for item in &mut matrix[rank][col..] {
                *item = gf65536_mul(*item, inv);
            }
            for row in 0..rows {
                if row == rank {
                    continue;
                }
                let factor = matrix[row][col];
                if factor == 0 {
                    continue;
                }
                for c in col..cols {
                    matrix[row][c] ^= gf65536_mul(matrix[rank][c], factor);
                }
            }
            rank += 1;
        }
        rank
    }
}
