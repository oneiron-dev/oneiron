"""Static SDK call-shape fixture: run mypy with MYPYPATH=python."""

from typing import Any

from oneiron.agent_verbs import TasksVerbs


def supported_ask_shapes(verbs: TasksVerbs, question: dict[str, Any]) -> None:
    verbs.ask({"intent_key": "rich", "what": question})
    verbs.ask("person", question)
    verbs.ask(["person"], question)
    verbs.ask({"person"}, question)
    verbs.ask(("person",), question)
    verbs.ask(None, question)
    verbs.ask({"people": ["person"]}, question)
