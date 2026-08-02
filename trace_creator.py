"""
Create an artificial UserTraces pickle file.

Each circuit gets one stream: (0.0, ip, assigned_port). Port assignment
follows the given ratios, same as before.

Client AS + destination AS/IP assignment (local files only, no network)
------------------------------------------------------------------------
By default (no extra flags needed beyond --ports/--total), every circuit
gets a client AS *and* a destination AS+IP, both drawn independently
from the same AS-density distribution - applying CLAPS's density
principle symmetrically to both ends of the circuit, computed entirely
from local files. No network access at runtime, ever - everything below
reads from disk.

This implements CLAPS's own density formula (Rochet et al., CCS 2020,
Sec. 6: "we take Tor's measured user-per-country statistics and
distribute users into ASes within their country proportional to the
number of IPv4 addresses each AS originates") using three local files:

  1. --pfx2as-file (default: in/pfx2as.tsv, REQUIRED - this is the only
     one of the three needed at all): a prefix-to-AS table, e.g.
     produced by build_pfx2as.py (+ merge_pfx2as.py) from RouteViews/
     RIPE RIS RIB dumps. Gives each AS's IPv4 address space. Format,
     tab-separated, one prefix per line:

         PREFIX    ORIGIN_ASNS[    EXTRA_COLUMN(S), ignored]

     - PREFIX is a CIDR block, e.g. "1.0.128.0/17".
     - ORIGIN_ASNS is one ASN, or a comma-separated list of candidate
       origin ASNs for that prefix (a MOAS case - this collector/merge
       saw the prefix originated by more than one AS). Any further
       tab-separated column (e.g. an observation count from
       merge_pfx2as.py) is read but ignored - its exact semantics
       weren't pinned down, so rather than mis-weight by it, every
       prefix (MOAS or not) just splits its address space evenly across
       however many origin ASNs are listed for it.
     - Prefixes broader than --min-prefix-len (default /8) are dropped
       as likely default-route/aggregation artifacts, not real address
       ownership - see load_pfx2as() docstring for why this matters
       (verified against a real "0.0.0.0/0" example that otherwise
       dominated the whole computation).

  2. --as-org-file (optional, e.g. CAIDA's as-org2info.txt): maps each
     AS to a country, by joining that file's two sections (org_id ->
     country, and aut -> org_id). Without this file, density is just
     each AS's global address-space share (--country-weight-mode
     defaults to 'address-space') - CLAPS's per-country split is skipped
     entirely, which is mathematically the SAME as grouping by country
     but weighting every country by its own total address space (the
     country grouping cancels out unless country weights come from
     something other than address space - see compute_as_density()).

  3. --country-userstats-file (optional, e.g. a locally-downloaded copy
     of Tor Metrics' userstats-relay-country.csv - columns
     date,country,users): real per-country Tor user counts, for
     weighting countries by actual usage rather than raw size. Requires
     --as-org-file too (need to know which AS is in which country).
     When given, --country-weight-mode defaults to 'userstats' - this is
     the closest reproduction of CLAPS's exact formula. Without it (but
     with --as-org-file), --country-weight-mode defaults to 'uniform':
     every country with at least one known AS gets equal total weight,
     regardless of size - a distinct (not obviously better or worse)
     choice from 'address-space', made explicit rather than silently
     picked; override with --country-weight-mode if neither default is
     what you want.

Note: output_with_rel.tsv (AS relationships / p2c-p2p) is NOT used here
- it's relevant to AS-*path* inference (which ASes lie between two
endpoints), a separate concern from this script's job of just assigning
a client/destination AS by density. If/when the network-adversary
analysis needs it, it belongs in whatever script walks the inferred path
between client and destination, not here.

Use --no-as-density to skip all of this and fall back to the original
"purely random public IP, no client AS" behavior (useful for quick
smoke tests, or if in/pfx2as.tsv isn't available yet).

Usage:
    # address-space-only density (no country data)
    python trace_creator.py --ports 443:70 80:30 --total 10000 \\
        --out in/artificial.traces.pickle

    # + country grouping, countries weighted equally
    python trace_creator.py --ports 443:70 80:30 --total 10000 \\
        --out in/artificial.traces.pickle --as-org-file in/as-org2info.txt

    # full CLAPS reproduction: real per-country Tor user counts
    python trace_creator.py --ports 443:70 80:30 --total 10000 \\
        --out in/artificial.traces.pickle \\
        --as-org-file in/as-org2info.txt \\
        --country-userstats-file in/userstats-relay-country.csv

    python trace_creator.py --ports 443:70 80:30 --total 10000 \\
        --out in/artificial.traces.pickle --no-as-density
"""

import sys
import os
import csv
import pickle
import random
import ipaddress
import argparse
from collections import defaultdict

# patch cPickle so models.py (written for Python 2) imports cleanly
sys.modules['cPickle'] = pickle
sys.path.insert(0, '.')
from models import UserTraces


DEFAULT_PFX2AS_PATH = '/scratch/enhance_pairwise/src/torps/network/pfx2_as.tsv'

# Hardcoded per-country circuit-count weights, read off the chat-provided
# chart (a "Circuits" bar chart by country, top 14 countries with error
# bars, y-axis in units of 1e8). Point-estimate values only (error bars
# not used) - these are eyeballed off the chart image, NOT exact
# published numbers, so nudge them if you have the precise source data.
# Used as the 'userstats' country_weight_mode's default weight source
# when --country-userstats-file isn't given (see compute_as_density()) -
# countries not in this table get zero weight in that mode.
DEFAULT_COUNTRY_USERSTATS = {
    'us': 3.15e8,
    'fr': 1.98e8,
    'ru': 1.38e8,
    'de': 1.38e8,
    'pl': 0.80e8,
    'ae': 0.65e8,
    'ca': 0.62e8,
    'es': 0.52e8,
    'vg': 0.47e8,
    'pr': 0.47e8,
    'ni': 0.47e8,
    'bm': 0.45e8,
    'nl': 0.45e8,
    'ss': 0.42e8,
}


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


def parse_int_ratio_pairs(pair_args):
    """Parses ["KEY:RATIO", ...] into (keys, normalized_ratios). KEY is
    parsed as int (works for both ports and AS numbers)."""
    keys, ratios = [], []
    for pr in pair_args:
        key_str, ratio_str = pr.split(':')
        keys.append(int(key_str))
        ratios.append(float(ratio_str))
    total = sum(ratios)
    ratios = [r / total for r in ratios]
    return keys, ratios


def parse_ports(port_args):
    """Kept as a thin wrapper for backwards compatibility with any
    external callers/imports that used this name specifically."""
    return parse_int_ratio_pairs(port_args)


def assign_counts(total, ratios):
    counts = []
    remaining = total
    for r in ratios[:-1]:
        n = int(round(total * r))
        counts.append(n)
        remaining -= n
    counts.append(remaining)
    return counts


def build_assignment_list(total, keys, ratios):
    """Builds a length-`total` list containing each key repeated according
    to assign_counts(), then shuffles it so key assignment isn't
    correlated with generation order (e.g. with port assignment). Only
    sensible for a small number of distinct keys (e.g. ports) - for the
    tens of thousands of ASes in the AS-density path below, plain
    weighted random sampling is used instead (see sample_weighted())."""
    counts = assign_counts(total, ratios)
    assignment = []
    for key, count in zip(keys, counts):
        assignment.extend([key] * count)
    random.shuffle(assignment)
    return assignment, counts


def sample_weighted(keys, weights, total):
    """Weighted random sample of size `total` from `keys` (with
    replacement), used for the AS-density path where the number of
    distinct categories (tens of thousands of ASes) makes the exact
    assign_counts()-based approach used for --ports meaningless."""
    return random.choices(keys, weights=weights, k=total)


### --- Local pfx2as.tsv loading --- ###

def load_pfx2as(path, min_prefix_len=8):
    """Parses a pfx2as.tsv file (see module docstring for format) into
    {asn: [(ip_network, share), ...]} for IPv4 entries only, where
    `share` is 1/N for a prefix listing N candidate origin ASNs (1.0 for
    an unambiguous single-origin prefix). Lines with 0 columns after
    stripping, or that fail to parse, are skipped. A 3rd+ tab-separated
    column (if present) is read but ignored - see module docstring.

    min_prefix_len: prefixes shorter than this (i.e. covering more
    addresses than a /min_prefix_len) are dropped rather than counted -
    real IPv4 allocations to a single AS are essentially never broader
    than a /8 in the modern routing table; anything broader (most
    commonly "0.0.0.0/0") seen in a pfx2as table is a default-route/
    aggregation artifact from the BGP collector, not real address
    ownership, and would otherwise swamp the whole density computation
    (verified against a real example: a 0.0.0.0/0 line with 4 origin
    ASNs gave each of those 4 ASes ~25% of the *entire* weight, versus
    0.001% for an AS that genuinely owns three real /17-/19 blocks)."""
    prefixes = defaultdict(list)
    n_lines, n_skipped, n_moas, n_too_broad = 0, 0, 0, 0
    with open(path) as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            n_lines += 1
            parts = line.split('\t')
            if len(parts) < 2:
                n_skipped += 1
                continue
            prefix_str, asn_field = parts[0], parts[1]
            try:
                network = ipaddress.ip_network(prefix_str, strict=False)
            except ValueError:
                n_skipped += 1
                continue
            if network.version != 4:
                n_skipped += 1
                continue
            if network.prefixlen < min_prefix_len:
                n_too_broad += 1
                continue
            asns = []
            for tok in asn_field.split(','):
                tok = tok.strip()
                if not tok:
                    continue
                try:
                    asns.append(int(tok))
                except ValueError:
                    pass
            if not asns:
                n_skipped += 1
                continue
            if len(asns) > 1:
                n_moas += 1
            share = 1.0 / len(asns)
            for asn in asns:
                prefixes[asn].append((network, share))
    if not prefixes:
        raise ValueError('{0} contained no usable IPv4 prefix/AS entries.'
            .format(path))
    print('Loaded {0}: {1} usable prefix lines ({2} skipped, {3} dropped '
        'as broader than /{4} - likely default-route/aggregation '
        'artifacts, {5} MOAS split evenly across listed origin ASNs), '
        '{6} distinct ASes.'.format(
            path, n_lines - n_skipped - n_too_broad, n_skipped,
            n_too_broad, min_prefix_len, n_moas, len(prefixes)))
    return dict(prefixes)


def as_address_space(entries):
    """Total (share-weighted) address space across a list of
    (ip_network, share) tuples, as produced by load_pfx2as()."""
    return sum(net.num_addresses * share for net, share in entries)


def random_ip_in_networks(entries):
    """Picks a (network, share)-weighted network - weighted by
    num_addresses * share, so contested/MOAS prefixes and smaller blocks
    are picked less often - then a random host address within it
    (avoiding network/broadcast addresses when the block is large enough
    to have them).

    NOTE: this rebuilds the (networks, weights) lists from scratch on
    every call, which is fine for a handful of calls but becomes a real
    bottleneck at trace_creator.py's --total scale (hundreds of
    thousands+), where the same AS - especially a big one with thousands
    of announced prefixes - gets picked as a destination many times over.
    Measured: ~460 calls/sec against a 5,000-prefix AS, vs ~6,900 calls/
    sec via build_ip_sampler()'s cached version below - a ~15x
    difference that alone can turn into minutes of apparently-frozen
    silence for a large --total run. main() uses build_ip_sampler() (with
    per-AS caching) instead of calling this directly in its per-row loop;
    this function is kept for any single-shot/legacy callers."""
    networks = [net for net, share in entries]
    weights = [net.num_addresses * share for net, share in entries]
    network = random.choices(networks, weights=weights, k=1)[0]
    if network.num_addresses <= 2:
        offset = random.randint(0, network.num_addresses - 1)
    else:
        offset = random.randint(1, network.num_addresses - 2)
    return str(ipaddress.ip_address(int(network.network_address) + offset))


def build_ip_sampler(entries):
    """Precomputes the (networks, weights) lists for one AS's prefix
    entries ONCE, returning a zero-arg callable that draws one random IP
    from them cheaply on every subsequent call - see the perf note on
    random_ip_in_networks() above for why this matters. main() keeps one
    of these per distinct destination AS (built lazily, on first use) and
    reuses it for every row assigned to that AS."""
    networks = [net for net, share in entries]
    weights = [net.num_addresses * share for net, share in entries]

    def _draw():
        network = random.choices(networks, weights=weights, k=1)[0]
        if network.num_addresses <= 2:
            offset = random.randint(0, network.num_addresses - 1)
        else:
            offset = random.randint(1, network.num_addresses - 2)
        return str(ipaddress.ip_address(int(network.network_address) + offset))

    return _draw


### --- Optional: local CAIDA as-org2info.txt for AS -> country --- ###

def load_as_country(path):
    """Parses a CAIDA as-org2info.txt file into {asn: country_code_lower}.
    The file has two sections, each introduced by its own '# format:'
    comment line (order in the file doesn't matter - detected by content,
    not position):
      '# format:org_id|changed|org_name|country|source'   -> org->country
      '# format:aut|changed|aut_name|org_id|opaque_id|source' -> AS->org
    AS -> country is then org_id join. ASes whose org has no country
    field (empty string) are dropped, same as ASes with no org entry at
    all - both cases are reported via the printed summary line."""
    org_country = {}
    as_orgid = {}
    section = None
    with open(path, encoding='utf-8', errors='replace') as f:
        for raw_line in f:
            line = raw_line.rstrip('\n')
            if not line:
                continue
            if line.startswith('#'):
                if 'format:org_id|' in line:
                    section = 'org'
                elif 'format:aut|' in line:
                    section = 'aut'
                continue
            parts = line.split('|')
            if section == 'org' and len(parts) >= 4:
                org_id, country = parts[0], parts[3]
                if country:
                    org_country[org_id] = country
            elif section == 'aut' and len(parts) >= 4:
                try:
                    asn = int(parts[0])
                except ValueError:
                    continue
                as_orgid[asn] = parts[3]

    as_country = {}
    n_no_org_or_country = 0
    for asn, org_id in as_orgid.items():
        country = org_country.get(org_id)
        if country:
            as_country[asn] = country.strip().lower()
        else:
            n_no_org_or_country += 1
    print('Loaded {0}: {1} orgs, {2} AS->org entries, {3} ASes resolved '
        'to a country ({4} dropped - no org or no country on file).'
        .format(path, len(org_country), len(as_orgid), len(as_country),
            n_no_org_or_country))
    return as_country


### --- Optional: local Tor Metrics-style per-country user counts --- ###

def load_country_userstats(path):
    """Parses a local copy of Tor Metrics' userstats-relay-country.csv
    (columns: date,country,users, or anything with at least 'country'
    and 'users') into {country_code_lower: most_recently_reported_users}.
    Separated into its own function so it can be unit-tested against
    hand-built CSV text."""
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or \
                ('country' not in reader.fieldnames) or \
                ('users' not in reader.fieldnames):
            raise ValueError(
                '{0} is missing expected "country"/"users" columns (got '
                '{1}).'.format(path, reader.fieldnames))
        has_date = 'date' in reader.fieldnames
        latest = {}  # country -> (date_str, users)
        for row in reader:
            country = (row.get('country') or '').strip().lower()
            if (not country) or (country == 'none'):
                continue
            try:
                users = float(row['users'])
            except (TypeError, ValueError):
                continue
            date = row.get('date', '') if has_date else ''
            prev = latest.get(country)
            if (prev is None) or (date >= prev[0]):
                latest[country] = (date, users)
    userstats = {c: u for c, (d, u) in latest.items()}
    print('Loaded {0}: {1} countries with a user count.'.format(
        path, len(userstats)))
    return userstats


### --- Combine into an AS density (CLAPS-style if country data given) --- ###

def compute_as_density(pfx2as_path, min_prefix_len=8, as_org_path=None,
        country_userstats_path=None, country_weight_mode=None):
    """Computes {asn: normalized_density_weight}. Three modes, chosen by
    country_weight_mode (or inferred from which optional files are given
    if left as None - see module docstring):

      'address-space' (default with no --as-org-file): density = AS's
        global IPv4 address-space share. No country step at all.

      'uniform' (only via explicit --country-weight-mode uniform): group
        AS space by country, but weight every country the SAME
        regardless of size - only possible once we know AS->country,
        hence requires --as-org-file.

      'userstats' (default with --as-org-file given, with or without
        --country-userstats-file): group AS space by country, weight
        each country by its real Tor user count - this is CLAPS's
        actual Sec. 6 formula. If --country-userstats-file is not
        given, falls back to DEFAULT_COUNTRY_USERSTATS, a hardcoded
        per-country user-count ratio eyeballed from a Tor Metrics
        "circuits by country" chart (see DEFAULT_COUNTRY_USERSTATS
        above) - not exact published numbers, but a reasonable
        default so this mode works with no extra file.

    Note 'address-space' and a hypothetical "weight countries by their
    own total address space" mode would be mathematically IDENTICAL
    (the country grouping cancels out in that case), which is why
    'address-space' is the only no-country-data option offered instead
    of pretending country grouping did something without real per-
    country weights to make it matter.

    Returns (density, prefixes, country_weight_mode) - prefixes is
    load_pfx2as()'s return value, handed back so callers can build actual
    destination IPs for whichever AS gets sampled; country_weight_mode is
    the mode actually used (resolved from None-means-auto, so callers
    can log/report it accurately).
    """
    prefixes = load_pfx2as(pfx2as_path, min_prefix_len=min_prefix_len)
    as_space = {asn: as_address_space(entries)
        for asn, entries in prefixes.items()}

    if country_weight_mode is None:
        if as_org_path is None:
            country_weight_mode = 'address-space'
        else:
            # 'userstats' is always available now, even without
            # --country-userstats-file, thanks to the
            # DEFAULT_COUNTRY_USERSTATS hardcoded fallback below - so it's
            # the default whenever we have AS->country data at all.
            # 'uniform' is still selectable via explicit
            # --country-weight-mode uniform.
            country_weight_mode = 'userstats'

    if country_weight_mode == 'address-space':
        total_space = sum(as_space.values())
        if total_space <= 0:
            raise RuntimeError('Computed AS address space is empty/zero '
                '- check {0}.'.format(pfx2as_path))
        density = {a: s / total_space for a, s in as_space.items() if s > 0}
        return density, prefixes, country_weight_mode

    if as_org_path is None:
        raise ValueError('country_weight_mode={0!r} requires --as-org-file.'
            .format(country_weight_mode))
    as_country = load_as_country(as_org_path)

    country_as_space = defaultdict(dict)  # country -> {asn: space}
    n_unmapped = 0
    for asn, space in as_space.items():
        if space <= 0:
            continue
        country = as_country.get(asn)
        if country is None:
            n_unmapped += 1
            continue
        country_as_space[country][asn] = space
    if n_unmapped:
        print('Note: {0} ASes from {1} have no known country (not in '
            '{2}) and get zero density in {3!r} mode.'.format(
                n_unmapped, pfx2as_path, as_org_path, country_weight_mode))

    if country_weight_mode == 'uniform':
        country_weight = {c: 1.0 for c in country_as_space}
    elif country_weight_mode == 'userstats':
        if country_userstats_path is None:
            print('Note: no --country-userstats-file given - falling back '
                'to built-in DEFAULT_COUNTRY_USERSTATS (hardcoded ratio '
                'eyeballed from a Tor Metrics "circuits by country" '
                'chart; not exact published figures).')
            userstats = DEFAULT_COUNTRY_USERSTATS
        else:
            userstats = load_country_userstats(country_userstats_path)
        country_weight = {c: userstats.get(c, 0.0) for c in country_as_space}
        n_no_userstats = sum(1 for w in country_weight.values() if w <= 0)
        if n_no_userstats:
            userstats_source = (country_userstats_path
                if country_userstats_path is not None
                else 'built-in DEFAULT_COUNTRY_USERSTATS')
            print('Note: {0}/{1} countries with known ASes have no Tor '
                'user count in {2} and get zero weight.'.format(
                    n_no_userstats, len(country_weight),
                    userstats_source))
    else:
        raise ValueError('Unknown country_weight_mode {0!r}.'.format(
            country_weight_mode))

    density = defaultdict(float)
    for country, as_space_in_country in country_as_space.items():
        weight = country_weight.get(country, 0.0)
        if weight <= 0:
            continue
        total_space_in_country = sum(as_space_in_country.values())
        if total_space_in_country <= 0:
            continue
        for asn, space in as_space_in_country.items():
            density[asn] += weight * (space / total_space_in_country)

    total_density = sum(density.values())
    if total_density <= 0:
        raise RuntimeError(
            "Computed AS density is empty in country_weight_mode={0!r} - "
            'check that countries in {1} actually have weight (userstats '
            'mode) and known ASes.'.format(country_weight_mode, as_org_path))
    density = {a: d / total_density for a, d in density.items()}
    print('Density computed in {0!r} mode over {1} ASes across {2} '
        'countries.'.format(country_weight_mode, len(density),
            len(country_as_space)))
    return density, prefixes, country_weight_mode


def main():
    parser = argparse.ArgumentParser(description='Create artificial traces pickle')
    parser.add_argument('--ports', nargs='+', default="80:0.52 1215:0.06 6890:0.2 6991:0.14 25:0.08", metavar='PORT:RATIO',
        help='Port and ratio pairs e.g. 443:70 80:30')
    parser.add_argument('--total', type=int, required=True,
        help='Total number of circuits/users to generate')
    parser.add_argument('--out', default='in/artificial.traces.pickle',
        help='Output pickle path (default: in/artificial.traces.pickle)')
    parser.add_argument('--name', default='circuit',
        help='Prefix for circuit key names (default: circuit -> circuit1, circuit2, ...)')
    parser.add_argument('--pfx2as-file', default=DEFAULT_PFX2AS_PATH,
        help='Path to the local pfx2as.tsv table used for AS density '
             '(default: {0}). See module docstring for expected format.'
             .format(DEFAULT_PFX2AS_PATH))
    parser.add_argument('--min-prefix-len', type=int, default=8,
        help='Drop pfx2as.tsv prefixes broader than this (default: 8, '
             'i.e. drop anything shorter than a /8 as a likely default-'
             'route/aggregation artifact rather than real address '
             'ownership - see load_pfx2as() docstring).')
    parser.add_argument('--as-org-file', default="/scratch/enhance_pairwise/src/torps/network/as2org/20260501.as-org2info.txt",
        help='Path to a local CAIDA as-org2info.txt (or equivalent) for '
             'AS->country mapping. Optional - enables country-grouped '
             'density (see module docstring for the three '
             '--country-weight-mode options this unlocks).')
    parser.add_argument('--country-userstats-file', default=None,
        help='Path to a local Tor Metrics-style userstats-relay-country '
             '.csv (columns: date,country,users) for real per-country '
             'Tor user weighting. Requires --as-org-file too.')
    parser.add_argument('--country-weight-mode', default=None,
        choices=['address-space', 'uniform', 'userstats'],
        help='Explicitly choose the density mode instead of letting it '
             'be inferred from which of --as-org-file / '
             '--country-userstats-file are given (see module docstring).')
    parser.add_argument('--no-as-density', action='store_true',
        help='Skip AS density entirely (don\'t even read --pfx2as-file) '
             'and fall back to the original behavior: purely random '
             'public IPs, no client AS encoded in circuit keys.')
    parser.add_argument('--seed', type=int, default=None,
        help='Random seed for reproducibility')
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    ports, port_ratios = parse_int_ratio_pairs(args.ports)
    port_list, port_counts = build_assignment_list(args.total, ports, port_ratios)

    client_as_list = None
    dest_as_list = None
    prefixes = None
    resolved_density_mode = None
    if not args.no_as_density:
        density, prefixes, resolved_density_mode = compute_as_density(
            args.pfx2as_file, min_prefix_len=args.min_prefix_len,
            as_org_path=args.as_org_file,
            country_userstats_path=args.country_userstats_file,
            country_weight_mode=args.country_weight_mode)
        as_keys = list(density.keys())
        as_weights = list(density.values())
        # client and destination are sampled independently from the same
        # density distribution - symmetric treatment of both ends of the
        # circuit (see module docstring / chat discussion).
        client_as_list = sample_weighted(as_keys, as_weights, args.total)
        dest_as_list = sample_weighted(as_keys, as_weights, args.total)

    # [perf] One IP sampler per distinct destination AS, built lazily on
    # first use and reused for every subsequent row assigned to that AS -
    # see build_ip_sampler()'s docstring for why this matters at scale
    # (a single big AS picked tens of thousands of times would otherwise
    # rebuild its weighted network list from scratch every single time).
    ip_samplers = {}
    progress_step = max(1, args.total // 20)  # ~20 progress lines total

    trace = {}
    for i in range(args.total):
        port = port_list[i]
        key = '{}{}'.format(args.name, i + 1)

        if client_as_list is not None:
            key += '_AS{}'.format(client_as_list[i])

        if dest_as_list is not None:
            dest_as = dest_as_list[i]
            sampler = ip_samplers.get(dest_as)
            if sampler is None:
                sampler = build_ip_sampler(prefixes[dest_as])
                ip_samplers[dest_as] = sampler
            ip = sampler()
        else:
            ip = random_public_ip()

        trace[key] = [(0.0, ip, port)]

        if (i + 1) % progress_step == 0 or (i + 1) == args.total:
            print('  ...{0}/{1} circuits generated ({2:.0f}%)'.format(
                i + 1, args.total, 100.0 * (i + 1) / args.total))

    ut = UserTraces.from_dict(trace)
    with open(args.out, 'wb') as f:
        pickle.dump(ut, f, protocol=2)

    print('Created {} circuits -> {}'.format(args.total, args.out))
    for port, count, ratio in zip(ports, port_counts, port_ratios):
        print('  port {:5d}: {:6d} circuits ({:.1f}%)'.format(
            port, count, ratio * 100))
    if client_as_list is not None:
        print('  client/destination AS assigned via {0!r} density over '
            '{1} ASes (from {2}).'.format(
                resolved_density_mode,
                len(set(client_as_list) | set(dest_as_list)),
                args.pfx2as_file))


if __name__ == '__main__':
    main()