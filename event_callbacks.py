### Classes that provide callback interface:
#     start(): called at start of simulation, before any other callback
#     set_network_state(cons_valid_after, cons_fresh_until, cons_bw_weights,
#         cons_bwweightscale, cons_rel_stats, descriptors): called every simulation period on new
#         consensus and descriptor data
#     set_sample_id(id): updates ID of current sample being executed
#     circuit_creation(circuit): called on successful circuit creation on circuit dict
#     stream_assignment(stream, circuit): called on assignment of stream to circuit
###

import sys

# [B6] Adversary fingerprint prefixes used by network_modifiers.AdversaryInsertion
# (add_adv_guards()/add_adv_exits()) - reused here to detect compromised nodes
# without importing that module.
_ADV_GUARD_PREFIX = '000000000000000000000000000000'
_ADV_EXIT_PREFIX = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'


def _iter_circuit_rows(circuit):
    """[B6] Normalizes an ordinary circuit dict (with a 'path' tuple of
    (guard, middle, exit)) and a conflux_set dict (with 'exit_node' and
    'legs', a list of (guard, middle) pairs sharing that exit) into a
    common iterator of (guard_fp, middle_fp, exit_fp, leg_index_or_None)
    tuples.

    For a conflux_set this yields *one row per leg* (so a single stream
    assigned to a 2-leg conflux set produces two rows here) - since which
    leg actually carried a given stream's traffic depends on per-leg RTT
    scheduling that this simulator does not model (see create_conflux_set()
    in pathsim.py), we surface *both* possible observation points rather
    than arbitrarily picking one and silently discarding the other.
    leg_index is None for an ordinary (non-conflux) circuit, and 0/1/...
    for each leg of a conflux set.
    """
    if 'path' in circuit:
        yield (circuit['path'][0], circuit['path'][1], circuit['path'][2], None)
    else:
        exit_fp = circuit['exit_node']
        for leg_index, (guard_fp, middle_fp) in enumerate(circuit['legs']):
            yield (guard_fp, middle_fp, exit_fp, leg_index)


def _is_adv_fingerprint(fp):
    """Returns True iff fp matches one of the synthetic adversary relay
    fingerprint prefixes used by network_modifiers.AdversaryInsertion."""
    return (fp[0:30] == _ADV_GUARD_PREFIX) or (fp[0:30] == _ADV_EXIT_PREFIX)


### Print just stream assignments in several possible formats ###
class PrintStreamAssignments(object):

    def __init__(self, format, testing, file=sys.stdout):
        self.format = format
        self.testing = testing
        self.file = file
        self.descriptors = None
        self.sample_id = None

    def start(self):
        """Prints log header for stream lines."""
        if self.testing:
            return
        if (self.format == 'testing'):
            pass
        elif (self.format == 'relay-adv'):
            self.file.write('Sample\tTimestamp\tCompromise Code\n')
        elif (self.format == 'network-adv'):
            self.file.write('Sample\tTimestamp\tGuard Fingerprint\tExit Fingerprint\tDestination IP\tConflux Leg\n')
        else:
            self.file.write('Sample\tTimestamp\tGuard Fingerprint\tMiddle Fingerprint\tExit Fingerprint\tDestination IP\tConflux Leg\n')

    def set_network_state(self, cons_valid_after, cons_fresh_until, cons_bw_weights,
        cons_bwweightscale, cons_rel_stats, descriptors):
        self.descriptors = descriptors

    def set_sample_id(self, id):
        self.sample_id = id

    def circuit_creation(self, circuit):
        pass

    def stream_assignment(self, stream, circuit):
        """Writes log line(s) to file (default stdout) showing client, time, IPs, and
        fingerprints in path of stream. [B6] For a conflux_set, writes one
        line per leg (see _iter_circuit_rows()) rather than crashing on
        circuit['path'], which conflux_set dicts don't have."""

        if self.testing:
            return

        if (circuit is None):
            if (self.format == 'testing'):
                pass
            else:
                self.file.write('{0}\t{1}\n'.format(self.sample_id, stream['time']))
            return

        if (stream['type'] == 'connect'):
            dest_ip = stream['ip']
        elif (stream['type'] == 'resolve'):
            dest_ip = 0
        else:
            raise ValueError('ERROR: Unrecognized stream in stream_assignment(): {0}'.\
                format(stream['type']))

        if (self.format == 'testing'):
            return

        if (self.format == 'relay-adv'):
            # [B6] For a conflux_set, guard_bad is true if *any* leg's
            # guard is compromised (exit is shared, so exit_bad is
            # unambiguous either way). This keeps 'relay-adv' as a single
            # scalar-per-stream code even for conflux, since it isn't
            # trying to report per-node fingerprints.
            guard_bad = False
            exit_bad = False
            for (guard_fp, middle_fp, exit_fp, leg_index) in _iter_circuit_rows(circuit):
                if _is_adv_fingerprint(guard_fp):
                    guard_bad = True
                if _is_adv_fingerprint(exit_fp):
                    exit_bad = True
            compromise_code = 0
            if (guard_bad and exit_bad):
                compromise_code = 3
            elif guard_bad:
                compromise_code = 1
            elif exit_bad:
                compromise_code = 2
            self.file.write('{0}\t{1}\t{2}\n'.format(self.sample_id, stream['time'],
                compromise_code))
        elif (self.format == 'network-adv'):
            for (guard_fp, middle_fp, exit_fp, leg_index) in _iter_circuit_rows(circuit):
                leg_str = '' if leg_index is None else str(leg_index)
                self.file.write('{0}\t{1}\t{2}\t{3}\t{4}\t{5}\n'.format(
                    self.sample_id, stream['time'], guard_fp, exit_fp,
                    dest_ip, leg_str))
        else:
            for (guard_fp, middle_fp, exit_fp, leg_index) in _iter_circuit_rows(circuit):
                leg_str = '' if leg_index is None else str(leg_index)
                self.file.write('{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\n'.format(
                    self.sample_id, stream['time'], guard_fp, middle_fp,
                    exit_fp, dest_ip, leg_str))
######

### Print relay compromised codes of stream assignments, compromise from input adv relays. ###
class PrintStreamAssignmentsAdvRelays(object):

    def __init__(self, adv_relays_filename, testing, file=sys.stdout):
        self.testing = testing
        self.file = file
        self.descriptors = None
        self.sample_id = None
        # store adversary relay fingerprints
        self.adv_relays = set()
        with open(adv_relays_filename, 'r') as f:
            for line in f:
                self.adv_relays.add(line.strip())
        if self.testing:
            print('Found {} adversary relays'.format(len(self.adv_relays)))

    def start(self):
        """Prints log header for stream lines."""
        
        if self.testing:
            return
        self.file.write('Sample\tTimestamp\tCompromise Code\n')

    def set_network_state(self, cons_valid_after, cons_fresh_until, cons_bw_weights,
        cons_bwweightscale, cons_rel_stats, descriptors):
        self.descriptors = descriptors

    def set_sample_id(self, id):
        self.sample_id = id

    def circuit_creation(self, circuit):
        pass

    def stream_assignment(self, stream, circuit):
        """Writes log line to file showing client, time and compromise codes:
        0 if guard & exit good, 1 if guard bad only, 2 if exit bad only, 3 if guard and exit bad.
        [B6] For a conflux_set, guard_bad is true if *any* leg's guard is
        in self.adv_relays (exit is shared across legs, so exit_bad is
        unambiguous either way) - this keeps the output a single
        scalar-per-stream code even for conflux."""

        if (circuit is None):
            return

        if self.testing:
            return

        guard_bad = False
        exit_bad = False
        for (guard_fp, middle_fp, exit_fp, leg_index) in _iter_circuit_rows(circuit):
            if (guard_fp in self.adv_relays):
                guard_bad = True
            if (exit_fp in self.adv_relays):
                exit_bad = True
        compromise_code = 0
        if (guard_bad and exit_bad):
            compromise_code = 3
        elif guard_bad:
            compromise_code = 1
        elif exit_bad:
            compromise_code = 2
        self.file.write('{0}\t{1}\t{2}\n'.format(self.sample_id, stream['time'], compromise_code))