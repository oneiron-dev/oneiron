"""Static-client metadata: the shipped stub, read the way a type checker reads it."""

import ast
from pathlib import Path

import oneiron


def test_retrieval_metadata_requires_a_boolean_partial_flag() -> None:
    # Parsed, never run: the stub imports agent_verbs relatively and takes
    # NotRequired from typing, which Python 3.10 does not have.
    stub = Path(oneiron.__file__).with_name("__init__.pyi")
    tree = ast.parse(stub.read_text())
    metadata = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RetrievalMeta"
    )
    assert [ast.unparse(base) for base in metadata.bases] == ["TypedDict"]
    assert not any(keyword.arg == "total" for keyword in metadata.keywords)
    fields = {
        node.target.id: ast.unparse(node.annotation)
        for node in metadata.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert fields["partial"] == "bool"
