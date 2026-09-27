"""Negative controls for the fixture scorer; run with python3 -m unittest."""
import unittest

from fixture_model_stub import complete


def request(model, data, instruction="Answer only from supplied evidence."):
    return {"model": model, "messages": [
        {"role": "system", "content": instruction},
        {"role": "user", "content": __import__("json").dumps(data)},
    ]}


class FixtureScorerTest(unittest.TestCase):
    def test_answer_requires_retrieved_support(self):
        question = "What is the updated contract launch code?"
        answer = lambda context: complete(request("gpt-4.1-2025-04-14", {
            "question": question, "context": context, "gold_answer": "tulip"}))
        self.assertEqual(answer("The contract launch code was updated from violet to tulip."), "tulip")
        self.assertEqual(answer("An earlier note used violet; no update is stated."), "unknown")
        self.assertEqual(answer("The contract launch code was updated from violet to rose."), "rose")
        self.assertEqual(answer(""), "unknown")

    def test_judge_rejects_unmatched_candidate(self):
        judge = lambda candidate: complete(request("gpt-4.1-mini-2025-04-14", {
            "question": "What is the updated contract launch code?",
            "candidate_answer": candidate, "gold_answer": "rose"}))
        self.assertEqual(judge("rose"), "1")
        self.assertEqual(judge("tulip"), "0")
        self.assertEqual(judge("unknown"), "0")


if __name__ == "__main__":
    unittest.main()
