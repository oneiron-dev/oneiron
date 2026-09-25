"""Installed JS/Python exact-key parity through the real authenticated server."""
import json
import os
from pathlib import Path
import subprocess

import pytest
from oneiron import Oneiron, OneironError


def _node(mode):
    project = Path(os.environ["WIRE_NODE_PROJECT"])
    result = subprocess.run(["node", str(project / "wire-key-value-parity.mjs"), mode],
                            env=os.environ.copy(), text=True, capture_output=True, check=True, timeout=180)
    return json.loads(result.stdout)


def _wire_item(item):
    if item is None:
        return None
    item = dict(item)
    item["created_at"] = item.pop("createdAt")
    item["updated_at"] = item.pop("updatedAt")
    return item


def test_remote_key_value_parity():
    memory = Oneiron.connect(os.environ["ONEIRON_WIRE_URL"], os.environ["ONEIRON_WIRE_KEY"])
    address = {"namespace": ["wire-key-parity", "exact"], "key": "preference"}
    first = _node("write")
    assert memory.key_value_get(address) == _wire_item(first["item"])
    receipt = memory.key_value_put({**address, "value": {"color": "green"},
                                    "request_id": "python-key-parity-two", "source": "user_stated"})
    second = _node("read")
    assert receipt["item"] == _wire_item(second["item"])
    assert memory.key_value_search({"namespace_prefix": ["wire-key-parity"]}) == [_wire_item(item) for item in second["search"]]
    assert memory.key_value_namespaces({"prefix": ["wire-key-parity"]}) == second["namespaces"]
    reader = Oneiron.connect(os.environ["ONEIRON_WIRE_URL"], os.environ["ONEIRON_WIRE_READ_KEY"])
    with pytest.raises(OneironError) as caught:
        reader.key_value_delete(address)
    assert caught.value.code == second["readDelete"] == "FORBIDDEN"
    deleted = _node("delete")
    assert deleted["receipt"]["existed"] is True
    assert deleted["item"] is None
    assert memory.key_value_get(address) is None
    assert memory.key_value_namespaces({"prefix": ["wire-key-parity"]}) == []
