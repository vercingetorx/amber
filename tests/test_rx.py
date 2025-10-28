from __future__ import annotations

import unittest

from amber.rx import sample_rx_combination, _add_to_basis, _reduce_row_dict


class RXSamplerTests(unittest.TestCase):
    def test_determinism_and_pivot(self):
        seed_base = b"SAMPLE-SEED-BASE!!"
        data_indices = list(range(16))
        for sid in range(10):
            a = sample_rx_combination(seed_base, sid, data_indices)
            b = sample_rx_combination(seed_base, sid, data_indices)
            self.assertEqual(a, b)
            pivot = data_indices[sid % len(data_indices)]
            self.assertTrue(any(si == pivot for si, _ in a))

    def test_rank_growth_small(self):
        seed_base = b"RANK-TEST-SEED-BASE"
        data_indices = list(range(12))
        basis = []
        # consume first k rows; confirm basis grows until hitting n
        for sid in range(1, 10):
            combo = sample_rx_combination(seed_base, sid - 1, data_indices)
            pos_map = {}
            for si, c in combo:
                pos = data_indices.index(si)
                pos_map[pos] = pos_map.get(pos, 0) ^ c
            # check if independent vs current basis
            reduced = _reduce_row_dict(pos_map, basis)
            if reduced:
                _add_to_basis(pos_map, basis)
            # At least monotonic non-decreasing rank
            self.assertLessEqual(len(basis), sid)
        self.assertGreaterEqual(len(basis), 5)


if __name__ == "__main__":
    unittest.main()
