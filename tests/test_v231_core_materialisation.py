"""Core-output projection must not allocate a position map it never consumes."""
import unittest
import numpy as np
import pandas as pd
from test_v231_performance import MODULE as M, CopyForbidden


class CoreMaterialisationTests(unittest.TestCase):
    def test_optional_position_map_preserves_rows_and_shared_sparse_payloads(self):
        frame = pd.DataFrame({"chronosift_row_id": [19, 7, 28, 16, 22], "value": list("abcde")},
            index=pd.DatetimeIndex(["2024-05-01T00:00:00Z"] * 5))
        signals = {0: {"fixture": 1.0}, 2: {}, 4: {"fixture": 2.0}}
        explanations = {0: [{"rule_id": "FIXTURE", "evidence": {"nested": [1, 2]}}], 2: []}
        state = {"signal_map": signals, "explain_map": explanations, "guard": CopyForbidden()}
        frame.attrs["chronosift_sparse"] = state
        mask = np.array([True, False, True, False, True])
        normal = M.ChronoSiftEngine._subset_sparse_state(frame, signals, explanations, mask)
        core = M.ChronoSiftEngine._subset_sparse_state(frame, signals, explanations, mask,
                                                      build_position_map=False)
        self.assertEqual(normal[3], {0: 0, 2: 1, 4: 2})
        self.assertEqual(core[3], {})
        self.assertIs(frame.attrs["chronosift_sparse"], state)
        with M._detached_sparse_state(core[0]), M._detached_sparse_state(normal[0]):
            pd.testing.assert_frame_equal(core[0], normal[0])
            self.assertEqual(core[0].chronosift_row_id.tolist(), [19, 28, 22])
        self.assertEqual(core[1], normal[1]); self.assertEqual(core[2], normal[2])
        self.assertIs(core[1][0], signals[0]); self.assertIs(core[1][1], signals[2])
        self.assertIs(core[2][0], explanations[0])
        self.assertIs(core[2][1], explanations[2])


if __name__ == "__main__":
    unittest.main()
