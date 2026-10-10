"""Compare complete NDJSON runs while preserving unit identity and event multiplicity.

Usage: python tests/compare-output.py baseline.ndjson candidate.ndjson
Unit identity is inferred from the first create/initial event. Ambiguous identities
are rejected rather than silently merging units. Ordering within one frame is not
part of this comparison; frame numbers and all other record content are retained.
"""
import collections
import json
from pathlib import Path
import sys


def normalized_records(path):
    rows = [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines()]
    if not rows or rows[0]['type'] != 'metadata' or rows[-1]['type'] != 'complete':
        raise ValueError(f'{path}: missing metadata or final completion record')
    ids = {}
    signatures = {}
    for row in rows:
        if row['type'] == 'unitEvent' and row['kind'] in ('initial', 'created'):
            unit_id = row['unitId']
            if unit_id in ids:
                continue
            signature = (row['frame'], row['playerId'], row['unitType'], tuple(row['position']))
            if signature in signatures:
                raise ValueError(f'{path}: ambiguous unit birth {signature}')
            ids[unit_id] = signature
            signatures[signature] = unit_id

    def normalize(value):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if (key == 'unitId' or key.endswith('UnitId') or key == 'transportId') and isinstance(item, int):
                    if item >= 0 and item not in ids:
                        raise ValueError(f'{path}: no lifecycle identity for {key}={item}')
                    result[key] = ids.get(item, item)
                else:
                    result[key] = normalize(item)
            return result
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value

    groups = collections.defaultdict(collections.Counter)
    for row in rows:
        normalized = normalize(row)
        if row['type'] == 'unitPositionSnapshot':
            normalized['units'].sort(key=lambda item: json.dumps(item, sort_keys=True))
        groups[row['type']][json.dumps(normalized, sort_keys=True)] += 1
    return groups, len(rows)


def main():
    if len(sys.argv) != 3:
        raise ValueError('usage: compare-output.py baseline.ndjson candidate.ndjson')
    baseline, count = normalized_records(sys.argv[1])
    candidate, candidate_count = normalized_records(sys.argv[2])
    failed = False
    for kind in sorted(baseline.keys() | candidate.keys()):
        missing = sum((baseline[kind] - candidate[kind]).values())
        extra = sum((candidate[kind] - baseline[kind]).values())
        if missing or extra:
            print(f'{kind}: {missing} missing, {extra} extra records')
            failed = True
    if failed:
        return 1
    print(f'Matched all {count} records ({candidate_count} candidate records).')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
