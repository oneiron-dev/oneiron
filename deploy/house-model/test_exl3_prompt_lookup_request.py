"""The per-request prompt-lookup switch (`PROMPT_LOOKUP_FIELD`): a request
that sets `"oneiron_prompt_lookup": false` takes no lookup proposal, and only
such a request changes its execution mode. CPU only, with the stand-ins of
`test_exl3_reply_limits`; no model is loaded. Run from this folder:
`python3 -m unittest test_exl3_prompt_lookup_request`."""
import sys
import types
import unittest
from unittest import mock

from test_exl3_reply_limits import prepared

import cache_usage
import exl3_server


class Tokens:
    """A sequence's ids, with no continuation past any match."""

    def __getitem__(self, key):
        return types.SimpleNamespace(shape=(1, 0))


class Sequence:
    def __init__(self):
        self.sequence_ids = types.SimpleNamespace(torch=Tokens)


class LookupJob:
    """A Job in a draft round, as `install_prompt_lookup` reads one."""

    def __init__(self, prompt_lookup=None):
        self.sequences = [Sequence()]
        self.draft_stats = []
        if prompt_lookup is not None:
            self.prompt_lookup = prompt_lookup

    def is_prefill_done(self):
        return True


class NoMatch:
    """A suffix automaton that never finds an earlier match."""

    def accept_tensor(self, ids):
        return 0, 0


class Generator:
    """A Generator whose own draft round reports that it ran."""

    def __init__(self, jobs):
        self.num_draft_tokens = 7
        self.active_jobs = jobs
        self.draft_rounds = 0

        def iterate_draftmodel_dflash_gen(results):
            self.draft_rounds += 1
            return None

        self.iterate_draftmodel_dflash_gen = iterate_draftmodel_dflash_gen


def installed_lookup(jobs):
    """A Generator over `jobs` with prompt lookup installed against
    stand-ins for torch and the exllamav3 extension."""
    ext_module = types.ModuleType("exllamav3.ext")
    ext_module.exllamav3_ext = types.SimpleNamespace(BC_SAM=NoMatch)
    modules = {"torch": types.ModuleType("torch"), "exllamav3.ext": ext_module}
    generator = Generator(jobs)
    with mock.patch.dict(sys.modules, modules):
        exl3_server.install_prompt_lookup(generator)
    return generator


class RequestField(unittest.TestCase):
    def test_lookup_stays_on_unless_the_request_turns_it_off(self):
        self.assertTrue(prepared({}).prompt_lookup)
        self.assertTrue(prepared({exl3_server.PROMPT_LOOKUP_FIELD: True}).prompt_lookup)
        self.assertFalse(prepared({exl3_server.PROMPT_LOOKUP_FIELD: False}).prompt_lookup)

    def test_a_value_other_than_true_or_false_is_refused(self):
        for value in ("false", 0, None):
            with self.subTest(value=value), self.assertRaises(exl3_server.RequestError):
                prepared({exl3_server.PROMPT_LOOKUP_FIELD: value})


class ExecutionMode(unittest.TestCase):
    def identity(self):
        identity = object.__new__(cache_usage.BackendIdentity)
        identity.server_settings = {"context": 32768, "speed_parts": ["prompt_lookup"]}
        return identity

    def test_only_a_request_with_lookup_off_changes_its_digest(self):
        identity = self.identity()
        kwargs = {"reasoning_effort": "medium"}
        before = cache_usage.settings_digest({"server": identity.server_settings, "template_kwargs": kwargs,
                                              "solo": False})
        self.assertEqual(identity.execution_mode(kwargs, False), before)
        self.assertEqual(identity.execution_mode(kwargs, False, True), before)
        self.assertNotEqual(identity.execution_mode(kwargs, False, False), before)


class LookupProposal(unittest.TestCase):
    def test_a_job_with_lookup_off_is_never_offered_one(self):
        off = LookupJob(prompt_lookup=False)
        on = LookupJob(prompt_lookup=True)
        unmarked = LookupJob()
        generator = installed_lookup([off, on, unmarked])
        self.assertIsNone(generator.iterate_draftmodel_dflash_gen(results=[]))
        # The draft ran the round, and only the jobs that allow lookup were matched.
        self.assertEqual(generator.draft_rounds, 1)
        self.assertFalse(hasattr(off, "lookup_matcher"))
        self.assertIsInstance(on.lookup_matcher, NoMatch)
        self.assertIsInstance(unmarked.lookup_matcher, NoMatch)


if __name__ == "__main__":
    unittest.main()
