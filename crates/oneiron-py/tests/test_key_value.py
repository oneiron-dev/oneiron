"""Actual Python/native/embedded round trip, not a recall-based mock."""
import pytest
from oneiron import Oneiron, OneironError


def test_exact_keyed_round_trip(tmp_path):
    memory = Oneiron.open(tmp_path / "vault")
    address = {"namespace": ["preferences"], "key": "color"}
    request = {**address, "value": {"name": "blue"}, "request_id": "one", "source": "user_stated"}
    assert memory.key_value_get(address) is None
    receipt = memory.key_value_put(request)
    assert receipt["item"]["value"] == request["value"]
    assert memory.key_value_put(request)["replayed"] is True
    assert memory.key_value_get(address) == receipt["item"]
    assert memory.key_value_search({"namespace_prefix": ["preferences"]}) == [receipt["item"]]
    assert memory.key_value_namespaces({}) == [["preferences"]]
    assert memory.key_value_delete(address)["existed"] is True
    assert memory.key_value_get(address) is None
    assert memory.key_value_delete(address)["existed"] is False
    with pytest.raises(OneironError) as caught:
        memory.key_value_put(request)
    assert caught.value.code == "INVALID_STATE"


def test_python_nonfinite_value_is_typed_bad_request(tmp_path):
    memory = Oneiron.open(tmp_path / "vault")
    with pytest.raises(OneironError) as caught:
        memory.key_value_put({"namespace": ["n"], "key": "k", "request_id": "nan", "value": {"n": float("nan")}})
    assert caught.value.code == "BAD_REQUEST"
