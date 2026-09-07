"""Installed-artifact quickstart and live four-verb parity gates for ONE-1441.

These are explicit CI entrypoints, outside the embedded package test directories.
A missing output, package, fixture, or Node helper fails rather than skips.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import time

import pytest

from oneiron import Oneiron, OneironError


def normalize(value):
    """Compare DTO field spelling; optional N-API fields omit Python's nulls."""
    if isinstance(value, dict):
        return {
            re.sub(r"[A-Z]", lambda match: "_" + match[0].lower(), key): normalize(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def assert_quickstart(result):
    result = normalize(result)
    assert result["witnessed"]["receipt_ref"].startswith("witness:")
    assert len(result["witnessed"]["message_short_ids"]) == 1
    claimed = result["claimed"]
    assert claimed["receipt_ref"].startswith("gate:")
    assert claimed["approval"] in {"auto", "proposed", "rejected"}
    assert result["recalled"]["pack_version"] == 1
    assert any(
        "window seat" in item["value_text"].lower()
        for item in result["recalled"]["items"]
    )
    assert result["receipts"]
    assert claimed["receipt_ref"] in {row["receipt_ref"] for row in result["receipts"]}
    for row in result["receipts"]:
        assert row["receipt_ref"].startswith("gate:")
        assert isinstance(row["outcome"], str)
        assert isinstance(row["reason_codes"], list)


def test_installed_quickstarts():
    results = Path(os.environ["WIRE_RESULTS"])
    for language in ("node", "python"):
        assert_quickstart(json.loads((results / f"{language}.json").read_text()))


def node_result(mode, *, occurred_at=None):
    project = Path(os.environ["WIRE_NODE_PROJECT"])
    env = os.environ.copy()
    if occurred_at is not None:
        env["WIRE_PARITY_OCCURRED_AT"] = str(occurred_at)
    result = subprocess.run(
        ["node", str(project / "wire-parity.mjs"), mode],
        cwd=project,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
        timeout=180,
    )
    return json.loads(result.stdout)


def refusal(operation, code):
    with pytest.raises(OneironError) as caught:
        operation()
    error = caught.value
    assert error.code == code
    assert error.message
    assert error.suggestions
    return {"code": error.code, "message": error.message, "suggestions": list(error.suggestions)}


def test_remote_sdk_parity():
    url = os.environ["ONEIRON_WIRE_URL"]
    memory = Oneiron.connect(url, os.environ["ONEIRON_WIRE_KEY"])
    # Standard recall uses the server's clock and type-specific recency decay.
    # Writes seconds apart can change rank between sequential SDK reads even
    # without a content write. Separate the fixture ages by weeks instead;
    # keep standard effort and compare the full ranked packs without sorting.
    fixture_now = int(time.time())
    node_written = node_result("write", occurred_at=fixture_now - 56 * 86400)
    assert_quickstart(node_written)
    occurred_at = fixture_now - 28 * 86400
    witnessed = memory.witness({
        "conversation_ref": "55555555555555555555555555555555",
        "occurred_at": occurred_at,
        "messages": [{
            "author": "user", "message_type": "dialogue",
            "content": "I prefer a window seat when I fly.", "order": 0,
        }],
    })
    claimed = memory.claim_upsert({
        "id": "66666666666666666666666666666666",
        "predicate": "preference.travel.seat", "subject_ref": witnessed["turn_short_id"],
        "value": {"seat": "window"}, "confidence": 1.0, "source": "user_stated",
        "occurred_at": occurred_at, "learned_at": occurred_at,
    })
    recalled = memory.recall("window seat")
    receipts = memory.receipts()
    assert_quickstart({
        "witnessed": witnessed, "claimed": claimed, "recalled": recalled, "receipts": receipts,
    })
    errors = {
        "deep": refusal(lambda: memory.recall("window seat", effort="deep"), "LEASE_REQUIRED"),
        "rebind": refusal(
            lambda: memory.as_actor("human:00000000000000000000000000000001"), "FORBIDDEN"
        ),
    }
    for name in ("ONEIRON_WIRE_NO_CLASS_KEY", "ONEIRON_WIRE_NO_PRINCIPAL_KEY"):
        unbound = Oneiron.connect(url, os.environ[name])
        errors[name] = refusal(unbound.receipts, "FORBIDDEN")
    reader = Oneiron.connect(url, os.environ["ONEIRON_WIRE_READ_KEY"])
    assert isinstance(reader.receipts(), list)
    errors["readWrite"] = refusal(lambda: reader.witness({
        "conversation_ref": "77777777777777777777777777777777",
        "messages": [{
            "author": "user", "message_type": "dialogue", "content": "refused", "order": 0,
        }],
    }), "FORBIDDEN")
    errors["readClaim"] = refusal(lambda: reader.claim_upsert({
        "predicate": "preference.travel.seat",
        "subject_ref": "33333333333333333333333333333333",
        "value": {"seat": "window"}, "confidence": 1.0, "source": "user_stated",
    }), "FORBIDDEN")

    # Both SDKs read the same committed content, but at different server times.
    # A second Python read must retain the ranked snapshot too: parity must not
    # hide an unstable fixture, missing items, or a changed binding field.
    node = node_result("read")
    assert normalize(memory.recall("window seat")) == normalize(recalled)
    assert normalize(node["recalled"]) == normalize(recalled)
    assert normalize(node["receipts"]) == normalize(receipts)
    assert normalize(memory.receipts()) == normalize(receipts)
    assert node["errors"] == errors

    # Both identical messages must survive. The newer Python message must
    # precede the older Node message, not their creation/ID order. This makes
    # the age separation load-bearing without normalizing away engine ranking.
    short_ids = [item["short_id"] for item in recalled["items"]]
    older = normalize(node_written)["witnessed"]["message_short_ids"][0]
    newer = witnessed["message_short_ids"][0]
    assert older in short_ids
    assert newer in short_ids
    assert short_ids.index(newer) < short_ids.index(older)
