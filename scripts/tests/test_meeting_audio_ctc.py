"""Synthetic acoustic-grid tests, not Ukrainian meeting qualification."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "meeting_audio_ctc.py"
spec = importlib.util.spec_from_file_location("meeting_audio_ctc", path)
ctc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctc)

class Refusal(Exception):
    pass

class CtcTests(unittest.TestCase):
    def test_repeated_label_requires_distinct_acoustic_frames_and_blank(self):
        emissions = [[0.0, -20.0], [-20.0, 0.0], [0.0, -20.0], [-20.0, 0.0], [0.0, -20.0]]
        self.assertEqual(ctc.token_spans(emissions, [1, 1], 0, Refusal), [(1, 2), (3, 4)])
        self.assertEqual(ctc.word_spans(emissions, [1, 1], [0, 1], ["л", "л"], 0, 1600, Refusal),
            [{"start_ms": 20, "end_ms": 40, "text": "л", "confidence": None},
             {"start_ms": 60, "end_ms": 80, "text": "л", "confidence": None}])
        with self.assertRaisesRegex(Refusal, "CtcAlignmentUnavailable"):
            ctc.token_spans(emissions[:2], [1, 1], 0, Refusal)

    def test_ukrainian_case_and_punctuation_keep_exact_original_words(self):
        vocabulary = {c: i + 1 for i, c in enumerate(sorted(ctc.UK_LETTERS | set("|' -") - {" "}))}
        words, tokens, owners = ctc.transcript_tokens("Привіт, п’ять!", vocabulary, 0, Refusal)
        self.assertEqual(words, ["Привіт,", "п’ять!"])
        self.assertEqual(tokens, [vocabulary[c] for c in "привіт|п'ять"])
        self.assertEqual(owners.count(None), 1)
        for text in ["слово 2026", "COVID", "ы", "!!!", "слово +"]:
            with self.assertRaisesRegex(Refusal, "UnalignableTranscript"):
                ctc.transcript_tokens(text, vocabulary, 0, Refusal)

    def test_bad_emissions_or_uncovered_tokens_never_gain_timestamps(self):
        for emissions, tokens in [([[float("nan"), 0]], [1]), ([[0, 1], [0]], [1]), ([[0, 1]], [3])]:
            with self.assertRaisesRegex(Refusal, "InvalidCtcEmissions"):
                ctc.token_spans(emissions, tokens, 0, Refusal)
        with self.assertRaisesRegex(Refusal, "CtcAlignmentUnavailable"):
            ctc.token_spans([], [1], 0, Refusal)
        with self.assertRaisesRegex(Refusal, "CtcAlignmentUnavailable"):
            ctc.token_spans([[0, 1]], [], 0, Refusal)

if __name__ == "__main__":
    unittest.main()
