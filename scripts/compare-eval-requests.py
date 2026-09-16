#!/usr/bin/env python3
"""Verify primary model requests match between synthetic evaluation runs.

Only enable_thinking is excluded. Recovery requests are counted separately;
all first attempts must match, including detector provenance order.
"""
import argparse
import copy
import json
from pathlib import Path


def primary_calls(record):
    calls = record['calls'] or []
    return [c for c in calls if not any(
        m.get('role') == 'user' and m.get('content', '').startswith(
            'The previous response was incomplete or invalid.')
        for m in c['request'].get('messages', []))]


def normalized(call):
    request = copy.deepcopy(call['request'])
    kwargs = request.get('chat_template_kwargs', {})
    kwargs.pop('enable_thinking', None)
    if not kwargs:
        request.pop('chat_template_kwargs', None)
    return {'stage': call['stage'], 'request': request}


def index(path):
    records = [json.loads(s) for s in path.read_text().splitlines()]
    keyed = {(r['name'], r['run']): r for r in records}
    if len(keyed) != len(records):
        raise ValueError('Duplicate fixture/run records')
    return keyed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('left', type=Path)
    parser.add_argument('right', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    left, right = index(args.left), index(args.right)
    if left.keys() != right.keys():
        raise ValueError('Different fixture/run selections')
    mismatches, matched, primary_total = [], 0, 0
    for key in left:
        a, b = left[key], right[key]
        for field in ['diff_sha256', 'expectation_sha256', 'model', 'prompt', 'prompt_deep']:
            if a[field] != b[field]:
                raise ValueError('Different input metadata: ' + field)
        x, y = primary_calls(a), primary_calls(b)
        primary_total += max(len(x), len(y))
        if len(x) != len(y):
            mismatches.append({'fixture': key[0], 'run': key[1], 'issue': 'different primary call count'})
            continue
        for ordinal, (first, second) in enumerate(zip(x, y), 1):
            if normalized(first) == normalized(second):
                matched += 1
            else:
                mismatches.append({'fixture': key[0], 'run': key[1], 'call': ordinal, 'stage': first['stage']})
    result = {'fixture_runs': len(left), 'primary_calls': primary_total,
              'matched_primary_calls': matched, 'mismatches': mismatches,
              'excluded_recovery_calls': [sum(len(r['calls'] or []) - len(primary_calls(r)) for r in group.values())
                                          for group in [left, right]]}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(mismatches))


if __name__ == '__main__':
    main()
