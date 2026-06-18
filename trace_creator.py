"""
Create an artificial UserTraces pickle file.

Each circuit gets one stream: (0.0, random_public_ip, assigned_port).
Port assignment follows the given ratios.

Usage:
    python trace_creator.py --ports 40:50 25:50 --total 10000 --out in/artificial.traces.pickle
"""

import sys
import pickle
import random
import argparse

# patch cPickle so models.py (written for Python 2) imports cleanly
sys.modules['cPickle'] = pickle
sys.path.insert(0, '.')
from models import UserTraces


def random_public_ip():
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        if a == 10: continue                          # 10.0.0.0/8
        if a == 127: continue                         # loopback
        if a == 172 and 16 <= b <= 31: continue       # 172.16.0.0/12
        if a == 192 and b == 168: continue            # 192.168.0.0/16
        if a == 169 and b == 254: continue            # link-local
        return '{}.{}.{}.{}'.format(a, b, c, d)


def parse_ports(port_args):
    ports, ratios = [], []
    for pr in port_args:
        port_str, ratio_str = pr.split(':')
        ports.append(int(port_str))
        ratios.append(float(ratio_str))
    total = sum(ratios)
    ratios = [r / total for r in ratios]
    return ports, ratios


def assign_counts(total, ratios):
    counts = []
    remaining = total
    for r in ratios[:-1]:
        n = int(round(total * r))
        counts.append(n)
        remaining -= n
    counts.append(remaining)
    return counts


def main():
    parser = argparse.ArgumentParser(description='Create artificial traces pickle')
    parser.add_argument('--ports', nargs='+', required=True, metavar='PORT:RATIO',
        help='Port and ratio pairs e.g. 443:70 80:30')
    parser.add_argument('--total', type=int, required=True,
        help='Total number of circuits/users to generate')
    parser.add_argument('--out', default='in/artificial.traces.pickle',
        help='Output pickle path (default: in/artificial.traces.pickle)')
    parser.add_argument('--name', default='circuit',
        help='Prefix for circuit key names (default: circuit -> circuit1, circuit2, ...)')
    parser.add_argument('--seed', type=int, default=None,
        help='Random seed for reproducibility')
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    ports, ratios = parse_ports(args.ports)
    counts = assign_counts(args.total, ratios)

    trace = {}
    idx = 1
    for port, count in zip(ports, counts):
        for _ in range(count):
            key = '{}{}'.format(args.name, idx)
            trace[key] = [(0.0, random_public_ip(), port)]
            idx += 1

    ut = UserTraces.from_dict(trace)
    with open(args.out, 'wb') as f:
        pickle.dump(ut, f, protocol=2)

    print('Created {} circuits -> {}'.format(args.total, args.out))
    for port, count, ratio in zip(ports, counts, ratios):
        print('  port {:5d}: {:6d} circuits ({:.1f}%)'.format(
            port, count, ratio * 100))


if __name__ == '__main__':
    main()
