"""The EXL3 server's answer schema (HOUSE-SCHEMA): a request's
`response_format` schema, else its `answer_schema` body field, the schema the
engine sends a Dreamer TURN extraction call as its own server's field. CPU
only, no model is loaded. Run from this folder:
`python3 -m unittest test_exl3_answer_schema`."""
import unittest

from test_exl3_reply_limits import stand_in_missing_gpu_modules

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


if __name__ == "__main__":
    unittest.main()
