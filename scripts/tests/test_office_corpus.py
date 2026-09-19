import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "office/corpus.py"
SPEC = importlib.util.spec_from_file_location("office_corpus", PATH)
CORPUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORPUS)


class OfficeCorpusTests(unittest.TestCase):
    def test_pinned_corpus_classifies_every_case(self):
        cases = CORPUS.load_cases()
        self.assertEqual(len(cases), 834)
        self.assertEqual(sum(CORPUS.classification(c) == "probe" for c in cases), 9)
        self.assertEqual(sum(CORPUS.classification(c) == "array" for c in cases), 44)

    def test_missing_caches_and_probes_cannot_inflate_score(self):
        cases = [dict(function="X", id="value", expected=1), dict(function="X", id="probe", expected=None)]
        self.assertEqual(CORPUS.score(cases, {})["X"], dict(passed=0, total=1, probes=1))
        result = {"value": dict(status="ok", value=True)}
        self.assertEqual(CORPUS.score(cases, result)["X"]["passed"], 0)
        result["value"]["value"] = 1.0
        self.assertEqual(CORPUS.score(cases, result)["X"]["passed"], 1)
        self.assertFalse(CORPUS.same_value(float("nan"), 1))


if __name__ == "__main__":
    unittest.main()
