import json
import os

from oneiron import Oneiron

credential = "v2.cred." + os.environ["ONEIRON_SECRET"].removeprefix("v2.slip.") + "." + os.environ["ONEIRON_BINDING_KEY"]
memory = Oneiron.connect(os.environ["ONEIRON_URL"], credential)

witnessed = memory.vault.witness(
    {
        "conversation_ref": "11111111111111111111111111111111",
        "messages": [
            {
                "author": "user",
                "message_type": "dialogue",
                "content": "I prefer a window seat when I fly.",
                "order": 0,
            }
        ],
    }
)

claimed = memory.vault.claims.upsert(
    {
        "id": "22222222222222222222222222222222",
        "predicate": "preference.travel.seat",
        "subject_ref": witnessed["turn_short_id"],
        "value": {"seat": "window"},
        "confidence": 1.0,
        "source": "user_stated",
    }
)
recalled = memory.vault.recall("window seat")
receipts = memory.vault.receipts()

print(
    json.dumps(
        {"witnessed": witnessed, "claimed": claimed, "recalled": recalled, "receipts": receipts},
        indent=2,
    )
)
