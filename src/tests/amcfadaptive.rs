    use std::collections::{BTreeMap, BTreeSet};

    use crate::gf256::{gf_inv, gf_mul};

    use super::{amcf_combinations_by_row, amcf_row_structure, sample_amcf_combination};

    #[test]
    fn amcf_has_stable_bridge_structure() {
        let rows = (0..12)
            .map(|row_id| amcf_row_structure(&[0x11; 16], row_id, 32, 12).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 12);
        assert_eq!(
            rows[0].positions,
            vec![0, 2, 4, 8, 11, 12, 16, 20, 24, 28]
        );
        assert_eq!(
            rows[2].positions,
            vec![2, 6, 8, 10, 14, 15, 18, 22, 26, 30]
        );
        assert_eq!(rows[11].target_size, 22);
        assert_eq!(
            rows[11].positions,
            vec![
                1, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 23, 24, 25, 27,
                28, 30, 31
            ]
        );
    }

    #[test]
    fn amcf_large_standard_coefficients_are_nonzero() {
        let data_indices = (0..236).collect::<Vec<_>>();
        let rows = (0..40)
            .map(|seed_id| {
                sample_amcf_combination(&[0x11; 16], seed_id, &data_indices, 40)
                    .unwrap()
                    .into_iter()
                    .collect::<BTreeMap<_, _>>()
            })
            .collect::<Vec<_>>();

        for row in &rows {
            assert!(!row.is_empty());
            assert!(row.values().all(|&coeff| coeff != 0));
        }
    }

    #[test]
    fn amcf_cauchy_coefficients_are_exact_no4_when_tags_fit_field() {
        let data_indices = (0..34).collect::<Vec<_>>();
        let rows = (0..12)
            .map(|seed_id| {
                sample_amcf_combination(&[0x11; 16], seed_id, &data_indices, 12)
                    .unwrap()
                    .into_iter()
                    .collect::<BTreeMap<_, _>>()
            })
            .collect::<Vec<_>>();

        assert_nonzero_no4_rows(&rows);
    }

    fn assert_nonzero_no4_rows(rows: &[BTreeMap<usize, u8>]) {
        for row in rows {
            assert!(!row.is_empty());
            assert!(row.values().all(|&coeff| coeff != 0));
        }
        for left_id in 0..rows.len() {
            for right in rows.iter().skip(left_id + 1) {
                let mut ratios = BTreeSet::new();
                for (&symbol_index, &left_coeff) in &rows[left_id] {
                    let Some(&right_coeff) = right.get(&symbol_index) else {
                        continue;
                    };
                    let ratio = gf_mul(left_coeff, gf_inv(right_coeff));
                    assert!(ratios.insert(ratio));
                }
            }
        }
    }

    #[test]
    fn amcf_standard_coefficients_are_total_for_dense_outer_rows() {
        for (data_count, row_count) in [(34, 12), (128, 40), (512, 130)] {
            let data_indices = (0..data_count).collect::<Vec<_>>();
            let rows = amcf_combinations_by_row(&data_indices, row_count).unwrap();
            assert_eq!(rows.len(), row_count);
            for row in rows {
                assert!(!row.is_empty());
                assert!(row.iter().all(|(_, coeff)| *coeff != 0));
            }
        }
    }
