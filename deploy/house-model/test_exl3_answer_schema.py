"""The EXL3 server's answer schema (HOUSE-SCHEMA): a request's
`response_format` schema, else its `answer_schema` body field, the schema the
engine sends a Dreamer TURN extraction call as its own server's field. CPU
only, no model is loaded. Run from this folder:
`python3 -m unittest test_exl3_answer_schema`."""
import os
import unittest
from pathlib import Path

from test_exl3_reply_limits import stand_in_missing_gpu_modules

try:
    import llguidance
except ImportError:
    llguidance = None

# The schema the engine sends a TURN extraction call (include_str! in executor/extraction.rs).
# ONEIRON_EXTRACTION_ANSWER_SCHEMA names another copy, for a server folder outside the repo.
SHIPPED_SCHEMA = Path(os.environ.get(
    "ONEIRON_EXTRACTION_ANSWER_SCHEMA",
    Path(__file__).resolve().parents[2]
    / "crates/oneiron/src/dreamer_consolidation/executor/extraction_answer_schema.json",
))

stand_in_missing_gpu_modules()
import exl3_server  # noqa: E402

SCHEMA = {"type": "object", "properties": {"candidates": {"type": "array"}}, "required": ["candidates"]}
OTHER = {"type": "object"}


class AnswerSchema(unittest.TestCase):
    def test_the_answer_schema_field_is_the_answer_schema(self):
        self.assertEqual(exl3_server.answer_schema({"answer_schema": SCHEMA}), SCHEMA)

    def test_a_response_format_schema_wins_over_the_field(self):
        body = {
            "response_format": {"type": "json_schema", "json_schema": {"name": "oneiron_response", "schema": OTHER}},
            "answer_schema": SCHEMA,
        }
        self.assertEqual(exl3_server.answer_schema(body), OTHER)

    def test_no_schema_without_either(self):
        self.assertIsNone(exl3_server.answer_schema({}))

    def test_a_field_that_is_not_an_object_is_refused(self):
        with self.assertRaises(exl3_server.RequestError):
            exl3_server.answer_schema({"answer_schema": "candidates"})


@unittest.skipIf(llguidance is None, "llguidance is not installed")
@unittest.skipUnless(SHIPPED_SCHEMA.is_file(), "the shipped extraction schema is not beside this folder")
class ShippedSchemaCompiles(unittest.TestCase):
    """LLGuidanceFilter compiles the request's schema per call, and a schema it cannot compile
    refuses every TURN extraction call (REQUEST_ERROR, no answer). A predicate `pattern` beside a
    `maxLength` was such a schema: llguidance 1.9.1 cannot tell whether their intersection is
    empty (HOUSE-SCHEMA comment test, 26 Nov)."""

    def test_the_shipped_extraction_schema_compiles_to_a_grammar(self):
        grammar = llguidance.grammar_from("json_schema", SHIPPED_SCHEMA.read_text())
        self.assertEqual(llguidance.LLMatcher.validate_grammar(grammar, None), "")


if __name__ == "__main__":
    unittest.main()
