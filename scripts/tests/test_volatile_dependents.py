"""Cells downstream of NOW/TODAY/RAND* are named by the truth's own formulas, so the bench never scores them."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/office"))
from volatile_dependents import references, volatile_dependents  # noqa: E402


class VolatileDependentTests(unittest.TestCase):
    def test_references_read_cells_ranges_sheets_columns_and_rows(self):
        rects = references('SUM(A1:B2)+Data!C3+\'My Sheet\'!$D$4+LOG10(E5)+COUNTIF(F:F,"A1")+SUM(7:7)', "S")
        self.assertEqual(rects, [("S", 1, 1, 2, 2), ("Data", 3, 3, 3, 3), ("My Sheet", 4, 4, 4, 4), ("S", 5, 5, 5, 5),
                                 ("S", 6, 1, 6, 1048576), ("S", 1, 7, 16384, 7)])

    def test_dependents_follow_chains_ranges_sheets_and_whole_columns(self):
        truth = {
            "S!A1": ("n", 1.0, "TODAY()"),
            "S!A2": ("n", 2.0, "A1+1"),            # direct
            "S!A3": ("n", 3.0, "SUM(A2:A2)"),      # through A2
            "S!B1": ("n", 2.0, "LOG10(100)"),      # LOG10 is not a cell
            "S!C1": ("n", 9.0, "COUNT(A:A)"),      # whole column holds A1
            "T!A1": ("n", 3.0, "S!A3*2"),          # cross-sheet
            "T!A2": ("n", 0.0, "'S'!B1"),          # reads a clean cell only
            "T!A3": ("s", "x", 'IF(A2,"A1","")'),  # A1 inside a string is not a reference
        }
        self.assertEqual(volatile_dependents(truth), {"S!A2", "S!A3", "S!C1", "T!A1"})

    def test_no_volatile_cell_means_nothing_is_skipped(self):
        self.assertEqual(volatile_dependents({"S!A1": ("n", 1.0, "A2+1"), "S!A2": ("n", 1.0, "")}), set())


if __name__ == "__main__":
    unittest.main()
