"""Ten saved drafts, exact values and UTC-minute schedules. Never sends."""
from datetime import datetime


def check(bundle, result):
    state = bundle["state"]
    expected = state["expected"]["drafts.json"]["drafts"]
    failures = []
    if len(expected) != 10 or state["drafts"] != expected:
        failures.append("drafts_mismatch")
    for draft in state["drafts"].values():
        value = draft["scheduled_time"]
        try:
            if datetime.strptime(value, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%dT%H:%M") != value:
                failures.append("schedule_not_utc_minute")
        except (ValueError, TypeError):
            failures.append("schedule_not_utc_minute")
    return result(failures)
