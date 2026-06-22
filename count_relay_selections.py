"""Count how many times each relay (IP address) was selected for each
position (Guard/Middle/Exit) in a TORPS simulation output file,
broken down by date and hour.

Usage:
    python count_relay_selections.py <simulate_output.txt> <out.pickle>

The output pickle contains a nested dict:
    {
        '<ip>': {
            '<YYYY-MM-DD>': {
                <hour 0-23>: {'Guard': n, 'Middle': n, 'Exit': n},
                ...
            },
            ...
        },
        ...
    }
Only roles that actually appear for a given (ip, date, hour) are stored.
"""

from __future__ import print_function
import sys
import datetime
try:
    import cPickle as pickle
except ImportError:
    import pickle
from collections import defaultdict

POSITION_COLUMNS = {
    'Guard IP': 'Guard',
    'Middle IP': 'Middle',
    'Exit IP': 'Exit',
}


def _nested():
    return defaultdict(lambda: defaultdict(int))


def count_relay_selections(in_path):
    """Returns {ip: {date_str: {hour: {role: count}}}}."""
    # counts[ip][date_str][hour][role] -> int
    counts = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(int))))

    with open(in_path, 'r') as f:
        header = f.readline().rstrip('\n').split('\t')

        try:
            ts_idx = header.index('Timestamp')
        except ValueError:
            raise ValueError('No Timestamp column found in header: {0}'.format(header))

        position_indices = {}
        for i, col in enumerate(header):
            if col in POSITION_COLUMNS:
                position_indices[i] = POSITION_COLUMNS[col]
        if not position_indices:
            raise ValueError(
                'No Guard/Middle/Exit IP columns found in header: {0}'.format(header))

        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            fields = line.split('\t')

            dt = datetime.datetime.utcfromtimestamp(int(fields[ts_idx]))
            date_str = dt.strftime('%Y-%m-%d')
            hour = dt.hour

            for i, position in position_indices.items():
                ip = fields[i]
                counts[ip][date_str][hour][position] += 1

    # convert nested defaultdicts to plain dicts
    return dict(
        (ip, dict(
            (date, dict(
                (hr, dict(role_counts))
                for hr, role_counts in hour_map.items()))
            for date, hour_map in date_map.items()))
        for ip, date_map in counts.items()
    )


def main():
    if len(sys.argv) != 3:
        print('Usage: python count_relay_selections.py <simulate_output.txt> <out.pickle>')
        sys.exit(1)

    in_path = sys.argv[1]
    out_path = sys.argv[2]

    counts = count_relay_selections(in_path)

    with open(out_path, 'wb') as f:
        pickle.dump(counts, f, pickle.HIGHEST_PROTOCOL)

    print('Counted selections for {0} relays.'.format(len(counts)))
    print('Wrote counts to {0}.'.format(out_path))


if __name__ == '__main__':
    main()
