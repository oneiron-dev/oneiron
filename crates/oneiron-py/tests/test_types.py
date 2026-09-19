"""Static-client metadata remains usable without importing the native engine."""

from pathlib import Path
import runpy
from typing import get_type_hints


def test_retrieval_metadata_requires_a_boolean_partial_flag() -> None:
    stub = Path(__file__).parents[1] / "python" / "oneiron" / "__init__.pyi"
    namespace = runpy.run_path(str(stub))
    metadata = namespace["RetrievalMeta"]
    assert get_type_hints(metadata, globalns=namespace)["partial"] is bool
    assert "partial" in metadata.__required_keys__
