"""The EXL3 server's output cap for a request with a thinking budget (FIX
DREAMER-EXTRACTION-THOUGHT-EATS-ANSWER-CAP). CPU only: the GPU modules the
server imports are stood in for when they are not installed, and no model is
loaded. Run from this folder: `python3 -m unittest test_exl3_reply_limits`."""
import sys
import types
import unittest


def stand_in_missing_gpu_modules():
    """Module stand-ins for exllamav3 and jinja2 when they are not installed:
    the server imports their names at load, and `Server.prepare` touches
    neither past the sampler it builds."""
    try:
        import exllamav3  # noqa: F401
        import exllamav3.generator.sampler  # noqa: F401
    except ImportError:
        class Named:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

        root = types.ModuleType("exllamav3")
        for name in ("Cache", "CacheLayer_quant", "Config", "Generator", "Job", "LLGuidanceFilter", "Model",
                     "Tokenizer"):
            setattr(root, name, type(name, (Named,), {}))
        generator = types.ModuleType("exllamav3.generator")
        sampler = types.ModuleType("exllamav3.generator.sampler")
        sampler.ComboSampler = type("ComboSampler", (Named,), {})
        root.generator = generator
        generator.sampler = sampler
        sys.modules.update({"exllamav3": root, "exllamav3.generator": generator,
                            "exllamav3.generator.sampler": sampler})
    try:
        import jinja2  # noqa: F401
    except ImportError:
        jinja2 = types.ModuleType("jinja2")
        jinja2.Environment = type("Environment", (), {})
        sys.modules["jinja2"] = jinja2


stand_in_missing_gpu_modules()
import exl3_server  # noqa: E402


class Ids:
    """A tokenized prompt of `count` tokens."""

    def __init__(self, count):
        self.count = count

    def cpu(self):
        return self

    def numel(self):
        return self.count


class Tokenizer:
    """Every text tokenizes to `prompt_tokens` tokens."""

    def __init__(self, prompt_tokens):
        self.prompt_tokens = prompt_tokens

    def encode(self, text, encode_special_tokens=True, add_bos=False):
        return Ids(self.prompt_tokens)


class ThinkingTemplate:
    """A chat template that leaves the prompt inside an open thought, as the
    house template does at a reasoning level."""

    def render(self, **kwargs):
        return "<|im_start|>assistant\n" + exl3_server.THINK_OPEN + "\n"


class Identity:
    def execution_mode(self, template_kwargs, solo):
        return "execution-mode"


def server(prompt_tokens, context=32768, default_max_tokens=4096):
    """A `Server` with no model behind it: enough for `prepare`."""
    serving = object.__new__(exl3_server.Server)
    serving.context = context
    serving.default_max_tokens = default_max_tokens
    serving.tokenizer = Tokenizer(prompt_tokens)
    serving.template = ThinkingTemplate()
    serving.identity = Identity()
    return serving


def prepared(body, prompt_tokens=1000):
    body = {"messages": [{"role": "user", "content": "Extract durable memory claims."}], **body}
    return server(prompt_tokens).prepare(body, "request-1", work=object())


class ReplyLimits(unittest.TestCase):
    def test_a_budget_with_no_cap_leaves_the_answer_the_default(self):
        # The Dreamer's extraction call before the fix: a 4,096-token budget
        # and no max_tokens. The cap was the 4,096 default, so a full thought
        # left the answer nothing.
        req = prepared({"reasoning_budget_tokens": 4096})
        self.assertTrue(req.thinking)
        self.assertEqual(req.cap, 4096)
        self.assertEqual(req.max_tokens, 8192)
        self.assertEqual(req.max_tokens - req.cap, 4096)

    def test_a_named_cap_stands(self):
        req = prepared({"reasoning_budget_tokens": 4096, "max_tokens": 12288})
        self.assertEqual((req.max_tokens, req.cap), (12288, 4096))
        req = prepared({"reasoning_budget_tokens": 4096, "max_completion_tokens": 6000})
        self.assertEqual((req.max_tokens, req.cap), (6000, 4096))

    def test_no_budget_keeps_the_default_cap(self):
        req = prepared({})
        self.assertEqual((req.max_tokens, req.cap), (4096, 4096))

    def test_the_context_room_still_cuts_the_cap(self):
        req = prepared({"reasoning_budget_tokens": 4096}, prompt_tokens=30000)
        self.assertEqual(req.max_tokens, 32768 - 30000)

    def test_a_negative_budget_is_refused(self):
        with self.assertRaises(exl3_server.RequestError):
            prepared({"reasoning_budget_tokens": -1})


if __name__ == "__main__":
    unittest.main()
