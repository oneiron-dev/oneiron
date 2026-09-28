#!/usr/bin/env python3
"""Validate editable v1 deck-review question/glossary data and supplied answers.

This is a policy packet check, not an LLM or modern-comment writer. SLD-03 owns
chat activation and applying the answers as a proposal.
"""
import argparse
import json
from pathlib import Path


def validate(seed: dict, answers: dict) -> dict:
    if seed.get('version') != 1 or seed.get('glossary', {}).get('version') != 1:
        raise ValueError('unsupported review seed or glossary version')
    questions = {q['id']: q for q in seed['questions']}
    if len(questions) != len(seed['questions']) or not questions:
        raise ValueError('question ids must be unique and nonempty')
    if answers.get('seed_version') != 1 or answers.get('glossary_version') != 1:
        raise ValueError('stale seed or glossary')
    rows, seen = [], set()
    for row in answers.get('answers', []):
        key = (row['question_id'], row['unit_id'])
        if key in seen or key[0] not in questions:
            raise ValueError('duplicate answer or unknown question')
        seen.add(key)
        if not row.get('evidence') or not row.get('unit_id'):
            raise ValueError('missing unit or evidence')
        probability = row['probability']
        if isinstance(probability, bool) or not isinstance(probability, (float, int)) or not 0 <= probability <= 1:
            raise ValueError('probability outside [0,1]')
        band = row['band']
        if band not in questions[key[0]].get('bands', ['low', 'medium', 'high']):
            raise ValueError('unknown band')
        rows.append({'question_id': key[0], 'unit_id': key[1], 'evidence': row['evidence'],
                     'probability': probability, 'band': band})
    return {'seed_version': 1, 'glossary_version': 1, 'answers': rows}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('answers', type=Path)
    p.add_argument('--seed', type=Path, default=Path(__file__).with_name('review_seed.json'))
    args = p.parse_args()
    print(json.dumps(validate(json.loads(args.seed.read_text()), json.loads(args.answers.read_text())), indent=2))


if __name__ == '__main__':
    main()
